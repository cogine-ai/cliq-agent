import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { listFixture } from './testing/list-fixture.js';

// Genuine Store/channel and production list query; these display-only rows
// deliberately lack authorization source history and confer no permission.
test('authorization capture uses the fixed ordered index and preserves full binary-ordered summaries', async t => {
  const fixture = await listFixture('authorization-ordered-capture');
  try {
    const session = await fixture.create('ordered-display'), start = Date.parse(session.createdAt);
    const rows = [{ id: 'display-z', offset: 0 }, { id: 'display-a', offset: 2 },
      { id: 'display-\uE000', offset: 1 }, { id: 'display-😀', offset: 1 }].map(({ id, offset }) => ({
      schemaVersion: 1, grantId: id, ownerPrincipalId: fixture.identity.principalId, state: 'consumed',
      target: { kind: 'dependency_install_scripts' }, targetDigest: 'd'.repeat(64), useCount: 1, rowVersion: 2,
      createdAt: new Date(start + offset).toISOString(), expiresAt: new Date(start + offset + 10000).toISOString(),
      consumedAt: new Date(start + offset + 1).toISOString()
    }));
    fixture.driver.transaction(connection => {
      const insert = connection.prepare('INSERT INTO authorization_grants(grant_id,owner_principal_id,state,row_json) VALUES(?,?,?,?)');
      for (const row of rows) insert.run(row.grantId, row.ownerPrincipalId, row.state, canonicalJsonBytes(row).toString('utf8'));
      const foreign = { ...rows[0]!, grantId: 'foreign', ownerPrincipalId: 'another-principal' };
      insert.run(foreign.grantId, foreign.ownerPrincipalId, foreign.state, canonicalJsonBytes(foreign).toString('utf8'));
    });
    const prototype = fixture.driver.readSnapshot(connection => Object.getPrototypeOf(connection)), prepare = prototype.prepare;
    const captured: string[] = [];
    t.mock.method(prototype, 'prepare', function(this: unknown, sql: string) {
      if (sql.startsWith('INSERT INTO temp.cliq_list_source(')) captured.push(sql.slice(sql.indexOf('SELECT ')));
      return Reflect.apply(prepare, this, [sql]);
    });
    const expected = [...rows].sort((a, b) => Buffer.compare(Buffer.from(a.createdAt), Buffer.from(b.createdAt)) ||
      Buffer.compare(Buffer.from(a.grantId), Buffer.from(b.grantId))).map(row => ({
      schemaVersion: 1, grantId: row.grantId, state: row.state, targetKind: row.target.kind, purpose: 'dependency_install_scripts',
      targetDigest: row.targetDigest, useCount: row.useCount, rowVersion: row.rowVersion, createdAt: row.createdAt,
      expiresAt: row.expiresAt, consumedAt: row.consumedAt
    }));
    for (const filters of [{}, { state: 'consumed' }, { targetKind: 'dependency_install_scripts' },
      { state: 'consumed', targetKind: 'dependency_install_scripts' }]) {
      const response = await fixture.store.listControl({ protocolVersion: 1, method: 'authorization.list', limit: 100, ...filters }, fixture.identity);
      assert(response.result.method === 'authorization.list');
      assert(canonicalJsonBytes(response.result.grants).equals(canonicalJsonBytes(expected)));
      assert.equal(response.result.nextCursor, undefined);
      const sql = captured.at(-1); assert(sql);
      const plan = fixture.driver.prepare('EXPLAIN QUERY PLAN ' + sql).all<{ detail: string }>(fixture.identity.principalId,
        ...('state' in filters ? [filters.state!] : []), ...('targetKind' in filters ? [filters.targetKind!] : []));
      assert(plan.some(row => row.detail.includes('authorization_grants_list_order_v1')));
      assert(!plan.some(row => row.detail.includes('USE TEMP B-TREE')), 'the complete captured payload must not be synchronously sorted');
    }
    assert.equal(captured.length, 4);
  } finally { t.mock.restoreAll(); await fixture.close(); }
});

test('ordered authorization capture still refuses malformed original fields without publishing a partial cut', async () => {
  const fixture = await listFixture('authorization-ordered-invalid');
  try {
    const session = await fixture.create('invalid-display'), at = session.createdAt;
    const original = { schemaVersion: 1, grantId: 'display', ownerPrincipalId: fixture.identity.principalId, state: 'active',
      target: { kind: 'dependency_install_scripts' }, targetDigest: 'd'.repeat(64), useCount: 0, rowVersion: 1,
      createdAt: at, expiresAt: new Date(Date.parse(at) + 10000).toISOString() };
    fixture.driver.transaction(connection => connection.prepare('INSERT INTO authorization_grants(grant_id,owner_principal_id,state,row_json) VALUES(?,?,?,?)')
      .run(original.grantId, original.ownerPrincipalId, original.state, canonicalJsonBytes(original).toString('utf8')));
    const request = { protocolVersion: 1 as const, method: 'authorization.list' as const, limit: 100 };
    const accepted = await fixture.store.listControl(request, fixture.identity);
    const counts = () => fixture.driver.prepare('SELECT (SELECT count(*) FROM list_read_cuts) AS cuts,(SELECT count(*) FROM list_read_cut_entries) AS entries').get();
    const before = counts();
    for (const changes of [{ createdAt: at + 'x' }, { createdAt: 'not-a-canonical-time' }, { grantId: 'x'.repeat(129) },
      { useCount: false }, { targetDigest: 'd'.repeat(65) }, { expiresAt: at }]) {
      fixture.driver.transaction(connection => connection.prepare('UPDATE authorization_grants SET row_json=? WHERE grant_id=?')
        .run(canonicalJsonBytes({ ...original, ...changes }).toString('utf8'), original.grantId));
      await assert.rejects(fixture.store.listControl(request, fixture.identity), { code: 'RECOVERY_REQUIRED' });
      assert.deepEqual(counts(), before);
    }
    const invalidUtf8 = Buffer.concat([Buffer.from('{"grantId":"'), Buffer.from([0x80]), Buffer.from('",'),
      canonicalJsonBytes(Object.fromEntries(Object.entries(original).filter(([key]) => key !== 'grantId'))).subarray(1)]);
    const preservedBom = canonicalJsonBytes({ ...original, grantId: '\uFEFFdisplay' });
    for (const bytes of [invalidUtf8, preservedBom]) {
      assert.equal(fixture.driver.prepare('SELECT json_valid(CAST(? AS TEXT)) AS valid').get<{ valid: bigint }>(bytes)!.valid, 1n);
      fixture.driver.transaction(connection => connection.prepare('UPDATE authorization_grants SET row_json=CAST(? AS TEXT) WHERE grant_id=?')
        .run(bytes, original.grantId));
      await assert.rejects(fixture.store.listControl(request, fixture.identity), { code: 'RECOVERY_REQUIRED' });
      assert.deepEqual(counts(), before, 'fatal UTF-8 and BOM preservation must precede any complete-cut publication');
    }
    fixture.driver.transaction(connection => connection.prepare('UPDATE authorization_grants SET row_json=? WHERE grant_id=?')
      .run(canonicalJsonBytes(original).toString('utf8'), original.grantId));
    assert(canonicalJsonBytes(await fixture.store.listControl(request, fixture.identity)).equals(canonicalJsonBytes(accepted)));
  } finally { await fixture.close(); }
});
