import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { decodeListRunSnapshot } from '../kernel/control-list.js';
import { decodeWireGrantSummary } from '../kernel/control-wire-data.js';
import type { RunSnapshotV1, RunSpec } from '../kernel/types.js';
import { insertArtifactMetadata } from './artifacts.js';
import { decodeAuthorizationGrant } from './authorization-artifacts.js';
import { ListCutCapacityError } from './list-read-cut.js';
import { DEFAULT_RUN_BUDGETS, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { listFixture, stopActualListChild } from './testing/list-fixture.js';

const MAX_ROWS = 100_000, MAX_BYTES = 64 * 1024 * 1024;
const zero = canonicalJsonBytes(ZERO_BUDGET).toString('utf8');
const displayId = (n: number) => `display-${String(n).padStart(6, '0')}`;
const request = (method: 'run.list' | 'authorization.list') => ({ protocolVersion: 1 as const, method, limit: 100 });
function cacheCounts(driver: SqliteDriver) {
  return { cuts: driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n,
    entries: driver.prepare('SELECT count(*) AS n FROM list_read_cut_entries').get<{ n: bigint }>()!.n };
}
function assertDisplayOnly(fixture: Awaited<ReturnType<typeof listFixture>>) {
  assert.equal(fixture.driver.prepare('PRAGMA foreign_keys').get<{ foreign_keys: bigint }>()!.foreign_keys, 1n);
  assert.equal(fixture.store.supportsInstalledRuns(), false);
  for (const table of ['worker_launches', 'run_journal'])
    assert.equal(fixture.driver.prepare(`SELECT count(*) AS n FROM ${table}`).get<{ n: bigint }>()!.n, 0n);
}
function completeCut(driver: SqliteDriver, cursor: string, expectedRows: number, expectedBytes: number) {
  const { cutId } = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  const row = driver.prepare('SELECT count(*) AS n,sum(length(CAST(payload_json AS BLOB))) AS bytes FROM list_read_cut_entries WHERE cut_id=?')
    .get<{ n: bigint; bytes: bigint }>(cutId)!;
  assert.equal(row.n, BigInt(expectedRows)); assert.equal(row.bytes, BigInt(expectedBytes));
}
async function captureIntegrity(t: TestContext, fixture: Awaited<ReturnType<typeof listFixture>>,
  method: 'run.list' | 'authorization.list', expectedRows: number, expectedBytes: number) {
  const original = await fixture.store.listControl(request(method), fixture.identity);
  const values = original.result.method === 'run.list' ? original.result.runs : original.result.grants;
  const ownerDriver = Reflect.get(fixture.store, 'driver') as SqliteDriver;
  const prototype = Object.getPrototypeOf(ownerDriver), transaction = prototype.transaction;
  for (const mutation of ['reorder', 'same_tuple', 'different_tuple'] as const) {
    const before = cacheCounts(fixture.driver);
    let writes = 0, changed = false, rejectedCandidate = false;
    t.mock.method(prototype, 'transaction', function (this: unknown, ...args: unknown[]) {
      const result = Reflect.apply(transaction, this, args);
      if (this === ownerDriver) {
        if (++writes === 2) {
          if (mutation === 'reorder') {
            ownerDriver.exec(`UPDATE temp.cliq_list_source SET ordinal=-ordinal WHERE ordinal IN (128,129);
              UPDATE temp.cliq_list_source SET ordinal=257+ordinal WHERE ordinal IN (-128,-129)`);
          } else {
            // Copy the whole captured display tuple, including the claimed id
            // for grants. The persistent source and its primary key never change.
            const columns = ownerDriver.prepare('PRAGMA temp.table_info(cliq_list_source)').all<{ name: string }>()
              .map(row => row.name).filter(name => name !== 'ordinal');
            assert(columns.length > 1 && columns.every(name => /^[a-z_]+$/u.test(name)));
            const names = columns.join(','), last = expectedRows;
            const first = ownerDriver.prepare('SELECT created_at FROM temp.cliq_list_source WHERE ordinal=1').get<{ created_at: string }>()!;
            ownerDriver.exec('UPDATE temp.cliq_list_source SET (' + names + ')=(SELECT ' + names +
              ' FROM temp.cliq_list_source WHERE ordinal=' + (mutation === 'same_tuple' ? 1 : last) +
              ') WHERE ordinal=' + (mutation === 'same_tuple' ? 2 : 1));
            if (mutation === 'different_tuple') {
              ownerDriver.prepare('UPDATE temp.cliq_list_source SET created_at=? WHERE ordinal=1')
                .run(new Date(Date.parse(first.created_at) - 1).toISOString());
              if (method === 'authorization.list') {
                // This fixture uses the full legal 24h TTL. Move expiry with
                // creation so the changed tuple remains a valid wire summary.
                const copied = ownerDriver.prepare('SELECT expires_at FROM temp.cliq_list_source WHERE ordinal=1')
                  .get<{ expires_at: string }>()!;
                ownerDriver.prepare('UPDATE temp.cliq_list_source SET expires_at=? WHERE ordinal=1')
                  .run(new Date(Date.parse(copied.expires_at) - 1).toISOString());
              }
              const pair = ownerDriver.prepare('SELECT id,created_at FROM temp.cliq_list_source WHERE ordinal IN (1,?) ORDER BY ordinal')
                .all<{ id: string; created_at: string }>(last);
              assert.equal(pair[0]!.id, pair[1]!.id); assert(pair[0]!.created_at < pair[1]!.created_at);
              const invalidOrder = ownerDriver.prepare(`SELECT EXISTS(SELECT 1 FROM (
                SELECT created_at,id,lag(created_at) OVER (ORDER BY ordinal) AS previous_time,
                  lag(id) OVER (ORDER BY ordinal) AS previous_id FROM temp.cliq_list_source)
                WHERE created_at<previous_time OR (created_at=previous_time AND CAST(id AS BLOB)<=CAST(previous_id AS BLOB))) AS invalid`)
                .get<{ invalid: bigint }>()!;
              assert.equal(invalidOrder.invalid, 0n, 'changed id tuple still has strict composite order');
            }
          }
          changed = true;
        } else if (writes === 3 && mutation === 'different_tuple') {
          assert.deepEqual(cacheCounts(fixture.driver), before, 'the non-current candidate must publish no cache rows');
          rejectedCandidate = true;
        }
      }
      return result;
    });
    try {
      if (mutation === 'different_tuple') {
        const response = await fixture.store.listControl(request(method), fixture.identity);
        assert(rejectedCandidate);
        assert.deepEqual(response.result.method === 'run.list' ? response.result.runs : response.result.grants, values);
        assert(response.result.nextCursor);
        completeCut(fixture.driver, response.result.nextCursor, expectedRows, expectedBytes);
        assert.deepEqual(cacheCounts(fixture.driver), { cuts: before.cuts + 1n, entries: before.entries + BigInt(expectedRows) });
      } else {
        await assert.rejects(fixture.store.listControl(request(method), fixture.identity), { code: 'RECOVERY_REQUIRED' });
        assert.deepEqual(cacheCounts(fixture.driver), before);
      }
      assert(changed);
    } finally { t.mock.restoreAll(); }
  }
}
// Canonical text permits non-NUL control characters. Count their actual JCS
// escape bytes rather than manufacturing an oversized or invalid source field.
function escapedText(contentBytes: number) {
  assert(Number.isSafeInteger(contentBytes) && contentBytes > 0);
  const value = '\u0001'.repeat(Math.floor(contentBytes / 6)) + 'p'.repeat(contentBytes % 6);
  assert(Buffer.byteLength(value) <= 128 && value.length > 0);
  assert.equal(canonicalJsonBytes(value).length - 2, contentBytes);
  return value;
}
async function actualStops(fixture: Awaited<ReturnType<typeof listFixture>>, method: 'run.list' | 'authorization.list',
  expectedRows: number, diagnostic: (value: string) => void) {
  await fixture.store.close();
  const stops = [], originalCuts = cacheCounts(fixture.driver);
  for (const phase of ['capture', 'prepare', 'final'] as const) {
    const stopped = await stopActualListChild(fixture.stateRoot, phase, diagnostic, method); stops.push(stopped);
    assert(stopped.componentInspection);
    assert.equal(stopped.componentInspection.originalSourceHistoryRefused, true);
    assert.equal(stopped.componentInspection.originalOwnerTerminal, true);
    assert.equal(stopped.componentInspection.activeOwners, 0);
    assert.equal(stopped.componentInspection.completeRowsPerPublishedCut, expectedRows);
    assert.equal(stopped.componentInspection.completeBytesPerPublishedCut, MAX_BYTES);
    assert.deepEqual(cacheCounts(fixture.driver), originalCuts);
  }
  diagnostic(JSON.stringify({ diagnosticOnly: true, kind: 'control_list_actual_sigterm_join', method,
    hostLoadControlled: false, stops, physicalInstalledSupervisorQualified: false }));
}

test('Run list applies row-count refusal before CAS reads, exact byte capacity and actual SIGTERM joins', async t => {
  const fixture = await listFixture('run-list-capacity');
  try {
    assertDisplayOnly(fixture);
    const session = await fixture.create('run-display-source'), at = session.createdAt;
    // Display-only rows: the complete RunSpec shape is real CAS data, but its
    // closure and checkpoint refer to absent context/workspace data, and no
    // WorkerLaunch, Journal, execution lease or admission authority is created.
    const absent = 'f'.repeat(64), checkpoint = 'display-checkpoint';
    const specification: RunSpec = { schemaVersion: 1, operation: 'agent', objectiveRef: absent, admittedContextRef: absent,
      baseWorkspaceManifestRef: absent, sourceProjectionRef: absent, assemblyRef: absent, policyRef: absent,
      sandboxProfileRef: absent, verifierSpecRef: absent, credentialGrantRefs: [], budgets: { ...DEFAULT_RUN_BUDGETS } };
    const spec = await fixture.store.artifacts.publishCanonical(specification, 'cliq-run-spec-v1');
    fixture.driver.transaction(connection => {
      insertArtifactMetadata(connection, spec, at);
      connection.prepare(`INSERT INTO checkpoints(id,schema_version,run_id,based_on_run_revision,run_item_seq,context_manifest_ref,
        journal_seq,workspace_state_ref,created_at,reason) VALUES(?,1,?,1,0,?,0,?,?,'initial')`)
        .run(checkpoint, displayId(1), absent, absent, at);
      connection.prepare(`INSERT INTO runs(id,session_id,spec_ref,status,next_step,revision,lease_epoch,latest_checkpoint_id,
        budget_reserved_json,budget_consumed_json,repair_count,result_ref,terminal_reason,cancel_requested,created_at,deadline_at,
        updated_at,principal_id,admission_method,admission_key,admission_intent_digest,admitted_request_digest)
        VALUES(?,?,?,'completed_unverified',NULL,1,0,?,?,?,0,?,'no_required_verifier',0,?,?,?,?,?,?,?,?)`)
        .run(displayId(1), session.id, spec.ref, checkpoint, zero, zero, absent, at, at, at,
          fixture.identity.principalId, 'display_fixture', displayId(1), absent, absent);
    });
    await assert.rejects(fixture.store.readRecoveryClosure(displayId(1)));
    const first = await fixture.store.listControl(request('run.list'), fixture.identity);
    assert(first.result.method === 'run.list' && first.result.runs.length === 1);
    const sample: RunSnapshotV1 = first.result.runs[0]!;
    decodeListRunSnapshot(sample);
    const minimalBytes = canonicalJsonBytes({ method: 'run.list', value: sample }).length;
    assert(minimalBytes * MAX_ROWS > MAX_BYTES, 'the legal minimal Run display corpus exceeds the byte cap before 100000 rows');
    const addDisplayRuns = (from: number, through: number) => fixture.driver.transaction(connection => connection.prepare(`WITH RECURSIVE counter(n) AS (VALUES(?) UNION ALL SELECT n+1 FROM counter WHERE n<?)
      INSERT INTO runs(id,session_id,spec_ref,status,next_step,revision,lease_epoch,latest_checkpoint_id,budget_reserved_json,
      budget_consumed_json,repair_count,result_ref,terminal_reason,cancel_requested,created_at,deadline_at,updated_at,principal_id,
      admission_method,admission_key,admission_intent_digest,admitted_request_digest)
      SELECT printf('display-%06d',n),?,?, 'completed_unverified',NULL,1,0,?,?,?,0,?,'no_required_verifier',0,?,?,?,?,
      'display_fixture',printf('display-%06d',n),?,? FROM counter`)
      .run(from, through, session.id, spec.ref, checkpoint, zero, zero, absent, at, at, at, fixture.identity.principalId, absent, absent));
    addDisplayRuns(2, 129);
    await captureIntegrity(t, fixture, 'run.list', 129, minimalBytes * 129);
    addDisplayRuns(130, MAX_ROWS + 1);
    const beforeCount = cacheCounts(fixture.driver);
    let specReads = 0;
    const prototype = Object.getPrototypeOf(fixture.store.artifacts), read = prototype.readCanonical;
    t.mock.method(prototype, 'readCanonical', function (this: unknown, ...args: unknown[]) {
      if (args[0] === spec.ref) specReads++;
      return Reflect.apply(read, this, args);
    });
    await assert.rejects(fixture.store.listControl(request('run.list'), fixture.identity), error => error instanceof ListCutCapacityError);
    assert.equal(specReads, 0, '100001 source rows must refuse before any display RunSpec CAS read');
    assert.deepEqual(cacheCounts(fixture.driver), beforeCount); t.mock.restoreAll();
    fixture.driver.transaction(connection => connection.prepare('DELETE FROM runs WHERE id=?').run(displayId(MAX_ROWS + 1)));
    await assert.rejects(fixture.store.listControl(request('run.list'), fixture.identity), error => error instanceof ListCutCapacityError);
    assert.deepEqual(cacheCounts(fixture.driver), beforeCount, '100000 real rows cannot publish a partial byte-overflow cut');

    const rows = 50_000, perRow = Math.floor(MAX_BYTES / rows), extra = MAX_BYTES % rows;
    const fixed = canonicalJsonBytes({ method: 'run.list', value: { ...sample, run: { ...sample.run, parentRunId: '' } } }).length;
    const small = escapedText(perRow - fixed), large = escapedText(perRow + 1 - fixed);
    fixture.driver.transaction(connection => {
      connection.prepare('DELETE FROM runs WHERE id>?').run(displayId(rows));
      connection.prepare('UPDATE runs SET parent_run_id=?').run(small);
      connection.prepare('UPDATE runs SET parent_run_id=? WHERE id<=?').run(large, displayId(extra));
    });
    const exact = await fixture.store.listControl(request('run.list'), fixture.identity);
    assert(exact.result.method === 'run.list' && exact.result.nextCursor);
    completeCut(fixture.driver, exact.result.nextCursor, rows, MAX_BYTES);
    const cursor = { ...request('run.list'), cursor: exact.result.nextCursor };
    const page = await fixture.store.listControl(cursor, fixture.identity), beforeByte = cacheCounts(fixture.driver);
    fixture.driver.transaction(connection => connection.prepare('UPDATE runs SET parent_run_id=? WHERE id=?').run(large, displayId(rows)));
    await assert.rejects(fixture.store.listControl(request('run.list'), fixture.identity), error => error instanceof ListCutCapacityError);
    assert.deepEqual(cacheCounts(fixture.driver), beforeByte);
    assert.deepEqual(canonicalJsonBytes(await fixture.store.listControl(cursor, fixture.identity)), canonicalJsonBytes(page));
    fixture.driver.transaction(connection => connection.prepare('UPDATE runs SET parent_run_id=? WHERE id=?').run(small, displayId(rows)));
    t.diagnostic(JSON.stringify({ diagnosticOnly: true, kind: 'run_list_actual_capacity', sourceRows: MAX_ROWS,
      minimalPublicPayloadBytes: minimalBytes, minimal100000Bytes: minimalBytes * MAX_ROWS, exactByteRows: rows, exactBytes: MAX_BYTES,
      rowLimitRejectedBeforeSpecRead: true, installedRunExecutionAuthorityCreated: false, physicalInstalledSupervisorQualified: false }));
    assertDisplayOnly(fixture);
    await actualStops(fixture, 'run.list', rows, text => t.diagnostic(text));
  } finally { t.mock.restoreAll(); await fixture.close(); }
});

test('authorization list preserves genuine bounded summary rows at 100000/64 MiB and joins actual SIGTERM', async t => {
  const fixture = await listFixture('authorization-list-capacity');
  try {
    assertDisplayOnly(fixture);
    const session = await fixture.create('authorization-display-source'), at = session.createdAt;
    // The summary projection is real, but this deliberately omits all channel,
    // request, core/row digest and consumption-receipt authority. It cannot be
    // decoded or consumed as a production AuthorizationGrant.
    const source = { schemaVersion: 1, grantId: displayId(1), ownerPrincipalId: fixture.identity.principalId,
      state: 'consumed', target: { kind: 'dependency_install_scripts' }, targetDigest: 'd'.repeat(64),
      useCount: 1, rowVersion: 2, createdAt: at, expiresAt: new Date(Date.parse(at) + 86_400_000).toISOString(),
      consumedAt: new Date(Date.parse(at) + 1).toISOString() };
    assert.throws(() => decodeAuthorizationGrant(source), TypeError);
    fixture.driver.transaction(connection => connection.prepare('INSERT INTO authorization_grants(grant_id,owner_principal_id,state,row_json) VALUES(?,?,?,?)')
      .run(source.grantId, fixture.identity.principalId, source.state, canonicalJsonBytes(source).toString('utf8')));
    const first = await fixture.store.listControl(request('authorization.list'), fixture.identity);
    assert(first.result.method === 'authorization.list' && first.result.grants.length === 1);
    const sample = first.result.grants[0]!; decodeWireGrantSummary(sample);
    const minimalBytes = canonicalJsonBytes({ method: 'authorization.list', value: sample }).length;
    const addDisplayGrants = (from: number, through: number) => fixture.driver.transaction(connection => connection.prepare(`WITH RECURSIVE counter(n) AS (VALUES(?) UNION ALL SELECT n+1 FROM counter WHERE n<?)
      INSERT INTO authorization_grants(grant_id,owner_principal_id,state,row_json)
      SELECT printf('display-%06d',n),?,'consumed',json_set(?,'$.grantId',printf('display-%06d',n)) FROM counter`)
      .run(from, through, fixture.identity.principalId, canonicalJsonBytes(source).toString('utf8')));
    addDisplayGrants(2, 129);
    await captureIntegrity(t, fixture, 'authorization.list', 129, minimalBytes * 129);
    addDisplayGrants(130, MAX_ROWS + 1);
    const beforeCount = cacheCounts(fixture.driver);
    await assert.rejects(fixture.store.listControl(request('authorization.list'), fixture.identity), error => error instanceof ListCutCapacityError);
    assert.deepEqual(cacheCounts(fixture.driver), beforeCount);
    fixture.driver.transaction(connection => connection.prepare('DELETE FROM authorization_grants WHERE grant_id=?').run(displayId(MAX_ROWS + 1)));
    const atCount = await fixture.store.listControl(request('authorization.list'), fixture.identity);
    assert(atCount.result.method === 'authorization.list' && atCount.result.nextCursor);
    completeCut(fixture.driver, atCount.result.nextCursor, MAX_ROWS, minimalBytes * MAX_ROWS);

    const perRow = Math.floor(MAX_BYTES / MAX_ROWS), extra = MAX_BYTES % MAX_ROWS;
    const small = escapedText(perRow - minimalBytes), large = escapedText(perRow + 1 - minimalBytes);
    assert(Buffer.byteLength(displayId(1) + large) <= 128);
    fixture.driver.transaction(connection => {
      // Both indexed and claimed identity change together in this inert test
      // metadata. The real source reader must preserve the original byte tuple.
      connection.prepare(`UPDATE authorization_grants SET grant_id=grant_id||?,row_json=json_set(row_json,'$.grantId',grant_id||?)`).run(small, small);
      connection.prepare(`UPDATE authorization_grants SET grant_id=substr(grant_id,1,14)||?,row_json=json_set(row_json,'$.grantId',substr(grant_id,1,14)||?)
        WHERE substr(grant_id,1,14)<=?`).run(large, large, displayId(extra));
    });
    const exact = await fixture.store.listControl(request('authorization.list'), fixture.identity);
    assert(exact.result.method === 'authorization.list' && exact.result.nextCursor);
    completeCut(fixture.driver, exact.result.nextCursor, MAX_ROWS, MAX_BYTES);
    const cursor = { ...request('authorization.list'), cursor: exact.result.nextCursor };
    const page = await fixture.store.listControl(cursor, fixture.identity), beforeByte = cacheCounts(fixture.driver);
    fixture.driver.transaction(connection => connection.prepare(`UPDATE authorization_grants SET grant_id=?,row_json=json_set(row_json,'$.grantId',?) WHERE grant_id=?`)
      .run(displayId(MAX_ROWS) + large, displayId(MAX_ROWS) + large, displayId(MAX_ROWS) + small));
    await assert.rejects(fixture.store.listControl(request('authorization.list'), fixture.identity), error => error instanceof ListCutCapacityError);
    assert.deepEqual(cacheCounts(fixture.driver), beforeByte);
    assert.deepEqual(canonicalJsonBytes(await fixture.store.listControl(cursor, fixture.identity)), canonicalJsonBytes(page));
    fixture.driver.transaction(connection => connection.prepare(`UPDATE authorization_grants SET grant_id=?,row_json=json_set(row_json,'$.grantId',?) WHERE grant_id=?`)
      .run(displayId(MAX_ROWS) + small, displayId(MAX_ROWS) + small, displayId(MAX_ROWS) + large));
    t.diagnostic(JSON.stringify({ diagnosticOnly: true, kind: 'authorization_list_actual_capacity', sourceRows: MAX_ROWS,
      minimalPublicPayloadBytes: minimalBytes, exactBytes: MAX_BYTES, originalBoundedCanonicalTextPreserved: true,
      usableAuthorizationGrantsCreated: 0, physicalInstalledSupervisorQualified: false }));
    assertDisplayOnly(fixture);
    await actualStops(fixture, 'authorization.list', MAX_ROWS, text => t.diagnostic(text));
  } finally { await fixture.close(); }
});
