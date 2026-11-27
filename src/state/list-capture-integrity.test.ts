// Genuine Store/read-only list capture with deliberately changed private
// display scratch. No Run, credential grant, native proof or lease is issued.
import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import type { SqliteDriver } from './sqlite-driver.js';
import { listFixture } from './testing/list-fixture.js';

test('fresh complete list rejects changed source order across the original batch boundary before publishing a cut', async t => {
  const fixture = await listFixture('capture-order');
  try {
    const original = await fixture.create('source');
    // Inert summary rows reference the genuine existing workspace. They do
    // not create execution, a context graph or another StateOwner.
    fixture.driver.transaction(connection => connection.prepare(`
      WITH RECURSIVE counter(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM counter WHERE n<129)
      INSERT INTO sessions(id,workspace_identity_ref,name,parent_session_id,forked_through_item_seq,context_revision,latest_item_seq,
        context_projection_ref,created_at,updated_at,principal_id,admission_method,admission_key,admission_intent_digest,admission_request_id)
      SELECT printf('display-%06d',n),?,NULL,NULL,NULL,1,0,?,?,?,?,'display_fixture',printf('display-%06d',n),?,NULL FROM counter`)
      .run(original.workspaceIdentityRef, original.contextProjectionRef, original.createdAt, original.updatedAt,
        fixture.identity.principalId, original.contextProjectionRef));
    const ownerDriver = Reflect.get(fixture.store, 'driver') as SqliteDriver;
    const prototype = Object.getPrototypeOf(ownerDriver), transaction = prototype.transaction;
    let writes = 0, changed = false;
    t.mock.method(prototype, 'transaction', function (this: unknown, ...args: unknown[]) {
      const result = Reflect.apply(transaction, this, args);
      if (this === ownerDriver && ++writes === 2) {
        ownerDriver.exec(`UPDATE temp.cliq_list_source SET ordinal=-ordinal WHERE ordinal IN (128,129);
          UPDATE temp.cliq_list_source SET ordinal=257+ordinal WHERE ordinal IN (-128,-129)`);
        changed = true;
      }
      return result;
    });
    await assert.rejects(fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 100 }, fixture.identity),
      { code: 'RECOVERY_REQUIRED' });
    assert(changed);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get()?.n, 0n);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cut_entries').get()?.n, 0n);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM worker_launches').get()?.n, 0n);
  } finally { t.mock.restoreAll(); await fixture.close(); }
});

async function changedCapture(t: TestContext, mutate: (driver: SqliteDriver) => void) {
  const fixture = await listFixture('capture-duplicate');
  t.after(async () => { t.mock.restoreAll(); await fixture.close(); });
  const sessions = [await fixture.create('first'), await fixture.create('second')];
  const ownerDriver = Reflect.get(fixture.store, 'driver') as SqliteDriver;
  const prototype = Object.getPrototypeOf(ownerDriver), transaction = prototype.transaction;
  let writes = 0, changed = false, rejectedCandidate = false;
  t.mock.method(prototype, 'transaction', function (this: unknown, ...args: unknown[]) {
    const result = Reflect.apply(transaction, this, args);
    if (this === ownerDriver) {
      if (++writes === 2) { mutate(ownerDriver); changed = true; }
      if (writes === 3) {
        assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get()?.n, 0n);
        assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cut_entries').get()?.n, 0n);
        rejectedCandidate = true;
      }
    }
    return result;
  });
  return { fixture, sessions, changed: () => changed, rejectedCandidate: () => rejectedCandidate };
}
const sourceColumns = 'id,workspace_identity_ref,name,parent_session_id,context_revision,latest_item_seq,created_at,updated_at';

test('fresh list refuses duplicate identical source tuples without relying on a TEMP unique index', async t => {
  const { fixture, changed } = await changedCapture(t, driver => {
    driver.exec('UPDATE temp.cliq_list_source SET (' + sourceColumns + ')=(SELECT ' + sourceColumns +
      ' FROM temp.cliq_list_source WHERE ordinal=1) WHERE ordinal=2');
  });
  await assert.rejects(fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 100 }, fixture.identity),
    { code: 'RECOVERY_REQUIRED' });
  assert(changed());
  assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get()?.n, 0n);
  assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cut_entries').get()?.n, 0n);
});

test('full final source equality still rejects a repeated id with another tuple and recaptures all original rows', async t => {
  const { fixture, sessions, changed, rejectedCandidate } = await changedCapture(t, driver => {
    const first = driver.prepare('SELECT created_at FROM temp.cliq_list_source WHERE ordinal=1').get<{ created_at: string }>()!;
    const earlier = new Date(Date.parse(first.created_at) - 1).toISOString();
    driver.exec('UPDATE temp.cliq_list_source SET (' + sourceColumns + ')=(SELECT ' + sourceColumns +
      ' FROM temp.cliq_list_source WHERE ordinal=2) WHERE ordinal=1');
    driver.prepare('UPDATE temp.cliq_list_source SET created_at=? WHERE ordinal=1').run(earlier);
    const rows = driver.prepare('SELECT id,created_at FROM temp.cliq_list_source ORDER BY ordinal').all<{ id: string; created_at: string }>();
    assert.equal(rows[0]!.id, rows[1]!.id); assert(rows[0]!.created_at < rows[1]!.created_at);
  });
  const response = await fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 100 }, fixture.identity);
  assert(changed()); assert(rejectedCandidate()); assert.equal(response.result.method, 'session.list');
  if (response.result.method !== 'session.list') assert.fail();
  assert.deepEqual(response.result.sessions.map(session => session.id).sort(), sessions.map(session => session.id).sort());
  assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get()?.n, 1n);
  assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cut_entries').get()?.n, 2n);
});
