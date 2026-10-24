import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import ts from 'typescript';
import * as sqlite from './sqlite-driver.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
const { assertSqliteConnectionOwnedBy, openSqliteDriver } = sqlite;

async function source(name: string) {
  return ts.createSourceFile(name, await readFile(new URL(name, import.meta.url), 'utf8'),
    ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}
function calls(node: ts.Node, name: string): ts.CallExpression[] {
  const result: ts.CallExpression[] = [];
  const visit = (current: ts.Node) => {
    if (ts.isCallExpression(current) && ts.isIdentifier(current.expression) && current.expression.text === name) result.push(current);
    ts.forEachChild(current, visit);
  };
  visit(node); return result;
}
function namedFunction(root: ts.Node, name: string): ts.FunctionDeclaration {
  const result: ts.FunctionDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root); assert.equal(result.length, 1, 'the production function is uniquely identified'); return result[0]!;
}
function namedVariable(root: ts.Node, name: string): ts.VariableDeclaration {
  const result: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root); assert.equal(result.length, 1, 'the production closure is uniquely identified'); return result[0]!;
}
function namedMethod(root: ts.Node, name: string): ts.MethodDeclaration {
  const result: ts.MethodDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root); assert.equal(result.length, 1, 'the production SQL callback is uniquely identified'); return result[0]!;
}
function scopedCalls(root: ts.Node, name: string, index: number, count: number) {
  const found = calls(root, name); assert.equal(found.length, count, 'all original checks remain present');
  for (const call of found) assert.equal(call.arguments[index]?.getText(), 'connection',
    'the original check receives the same explicit SQL scope');
}

test('publication worker SQL receivers remain usable in the genuine owning transaction without enabling the outer driver', async () => {
  const root = await source('./run-execution.ts'), worker = namedFunction(root, 'assertCurrentWorker');
  const names = ['readRun', 'assertLiveDispatchState', 'assertActiveStateOwner'];
  const receivers = names.map(name => {
    const found = calls(worker, name); assert.equal(found.length, 1, 'all three original SQL checks remain present');
    const argument = found[0]!.arguments[0]!;
    assert(ts.isIdentifier(argument), 'the SQL receiver is a fixed local connection, not an injected callback');
    return argument.text;
  });
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-sql-scope-'));
  const driver = openSqliteDriver(path.join(directory, 'state.sqlite'));
  try {
    driver.exec('CREATE TABLE scope_records(value INTEGER) STRICT; INSERT INTO scope_records VALUES(17)');
    driver.transaction(connection => {
      // These are the actual production receiver expressions only. No Run,
      // StateOwner, worker, native handle or successful authority is fabricated.
      for (const name of receivers) {
        const actual: SqliteConnection = name === 'driver' ? driver : name === 'connection' ? connection :
          assert.fail('the production SQL receiver must remain a fixed driver or connection identifier');
        assert.equal(actual.prepare('SELECT value FROM scope_records').get<{ value: bigint }>()!.value, 17n,
          'publication SQL reads must use the real owning transaction connection');
      }
      assert.throws(() => driver.prepare('SELECT value FROM scope_records'),
        /outer SQLite connection is unavailable/u, 'the outer driver guard must remain closed');
    });
  } finally { driver.close(); await rm(directory, { recursive: true, force: true }); }
});

test('claimed publication and preparation history receivers stay inside the genuine owning transaction', async () => {
  const root = await source('./publication-invocation.ts');
  const reads = [
    ...calls(namedFunction(root, 'claimedBinding'), 'assertActiveStateOwner'),
    ...calls(namedFunction(root, 'claimedBinding'), 'readInvocationAttempt'),
    ...calls(namedFunction(root, 'assertUnclaimedPreparation'), 'assertActiveStateOwner'),
    ...calls(namedFunction(root, 'assertUnclaimedPreparation'), 'readInvocationAttempt'),
    ...calls(namedFunction(root, 'originalInitialAmbiguity'), 'assertActiveStateOwner')
  ];
  assert.equal(reads.length, 5, 'all original owner and retained-history reads remain present');
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-completion-sql-'));
  const driver = openSqliteDriver(path.join(directory, 'state.sqlite'));
  try {
    driver.exec('CREATE TABLE scope_records(value INTEGER) STRICT; INSERT INTO scope_records VALUES(31)');
    driver.transaction(connection => {
      for (const call of reads) {
        // Execute the actual production receiver expression, not fabricated
        // publication, StateOwner, Run or native authority.
        const receiver = call.arguments[0]!.getText();
        const actual = receiver === 'connection' ? connection : receiver === 'driver' || receiver === 'held.driver' ? driver :
          assert.fail('publication SQL reads use only their fixed original driver or explicit scope');
        assert.equal(actual.prepare('SELECT value FROM scope_records').get<{ value: bigint }>()!.value, 31n,
          'original completion reads must not re-enter the unavailable outer connection');
      }
      assert.throws(() => driver.prepare('SELECT value FROM scope_records'), /outer SQLite connection is unavailable/u);
    });
  } finally { driver.close(); await rm(directory, { recursive: true, force: true }); }
});

test('SQL connection provenance accepts only the exact live issuing scope and leaves rollback and outer guards intact', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-sql-issuer-'));
  const driver = openSqliteDriver(path.join(directory, 'state.sqlite'));
  const other = openSqliteDriver(path.join(directory, 'other.sqlite'));
  const marker = new Error('original transaction rejection');
  let expired!: SqliteConnection;
  try {
    driver.exec('CREATE TABLE scope_records(value INTEGER) STRICT; INSERT INTO scope_records VALUES(17)');
    assertSqliteConnectionOwnedBy(driver, driver);
    driver.transaction(connection => {
      expired = connection;
      assertSqliteConnectionOwnedBy(driver, connection);
      assert.throws(() => assertSqliteConnectionOwnedBy(driver, driver), /outer SQLite connection is unavailable/u);
      assert.throws(() => assertSqliteConnectionOwnedBy(other, connection), TypeError);
      assert.throws(() => assertSqliteConnectionOwnedBy(driver, other), TypeError);
      assert.equal(connection.prepare('SELECT value FROM scope_records').get<{ value: bigint }>()!.value, 17n);
      other.transaction(foreign => assert.throws(() => assertSqliteConnectionOwnedBy(driver, foreign), TypeError));
    });
    assert.throws(() => assertSqliteConnectionOwnedBy(driver, expired), TypeError);
    driver.transaction(current => {
      assertSqliteConnectionOwnedBy(driver, current);
      assert.throws(() => assertSqliteConnectionOwnedBy(driver, expired), TypeError);
    });
    assert.throws(() => driver.transaction(connection => {
      expired = connection; assertSqliteConnectionOwnedBy(driver, connection);
      connection.prepare('UPDATE scope_records SET value=99').run(); throw marker;
    }), error => error === marker);
    assert.throws(() => assertSqliteConnectionOwnedBy(driver, expired), TypeError);
    assertSqliteConnectionOwnedBy(driver, driver);
    assert.equal(driver.prepare('SELECT value FROM scope_records').get<{ value: bigint }>()!.value, 17n,
      'the original error rolls back the real write');
    driver.readSnapshot(connection => {
      expired = connection; assertSqliteConnectionOwnedBy(driver, connection);
      assert.equal(connection.prepare('SELECT value FROM scope_records').get<{ value: bigint }>()!.value, 17n);
      assert.throws(() => connection.prepare('UPDATE scope_records SET value=100').run(),
        /readonly|read-only/iu, 'provenance does not turn a read snapshot into a writer');
      assert.throws(() => assertSqliteConnectionOwnedBy(driver, driver), /outer SQLite connection is unavailable/u);
    });
    assert.throws(() => assertSqliteConnectionOwnedBy(driver, expired), TypeError);
  } finally {
    driver.close(); other.close();
    assert.throws(() => assertSqliteConnectionOwnedBy(driver, driver), TypeError);
    await rm(directory, { recursive: true, force: true });
  }
});

test('SQL connection provenance rejects forged and proxied inputs before any getter, trap or SQL call', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-sql-unissued-'));
  const driver = openSqliteDriver(path.join(directory, 'state.sqlite'));
  let observed = 0;
  const hostile = Object.create(null, {
    prepare: { get() { observed++; throw new Error('untrusted SQL getter'); } },
    exec: { get() { observed++; throw new Error('untrusted SQL getter'); } }
  }) as SqliteConnection;
  const handler: ProxyHandler<SqliteConnection> = {
    get() { observed++; throw new Error('untrusted get trap'); },
    getPrototypeOf() { observed++; throw new Error('untrusted prototype trap'); },
    getOwnPropertyDescriptor() { observed++; throw new Error('untrusted descriptor trap'); },
    ownKeys() { observed++; throw new Error('untrusted keys trap'); }
  };
  try {
    driver.transaction(connection => {
      const forged = Object.assign(Object.create(Object.getPrototypeOf(connection)), { active: true });
      const reflected = Reflect.construct(Object.getPrototypeOf(connection).constructor,
        [driver, Object.create(null)]) as SqliteConnection;
      for (const value of [hostile, forged, reflected, new Proxy(connection, handler), new Proxy(hostile, handler)]) {
        assert.throws(() => assertSqliteConnectionOwnedBy(driver, value), TypeError);
      }
      assert.throws(() => assertSqliteConnectionOwnedBy(new Proxy(driver, handler) as SqliteDriver, connection), TypeError);
      assert.throws(() => assertSqliteConnectionOwnedBy(Object.create(Object.getPrototypeOf(driver)) as SqliteDriver, connection), TypeError);
      assert.equal(observed, 0, 'rejecting unissued identities must not evaluate caller behavior');
      assertSqliteConnectionOwnedBy(driver, connection);
      assert.equal(connection.prepare('SELECT 23 AS value').get<{ value: bigint }>()!.value, 23n);
    });
    assert.equal(observed, 0);
  } finally { driver.close(); await rm(directory, { recursive: true, force: true }); }
});

test('SQL issuer revocation cannot be suppressed by replacing a returned scope method', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-sql-scope-revocation-'));
  const driver = openSqliteDriver(path.join(directory, 'state.sqlite'));
  let expired!: SqliteConnection;
  try {
    driver.transaction(connection => {
      expired = connection;
      // No SQL/Run authority is manufactured: this is the genuine callback
      // object. Its caller-visible method cannot own the private issuer Map.
      Object.defineProperty(connection, 'deactivate', { value() {}, configurable: true });
      assertSqliteConnectionOwnedBy(driver, connection);
    });
    assert.throws(() => assertSqliteConnectionOwnedBy(driver, expired), TypeError,
      'the driver itself must revoke the issuer at the original scope boundary');
    driver.transaction(connection => {
      assertSqliteConnectionOwnedBy(driver, connection);
      assert.throws(() => assertSqliteConnectionOwnedBy(driver, expired), TypeError);
    });
  } finally { driver.close(); await rm(directory, { recursive: true, force: true }); }
});

test('publication resource friends keep their original brands and validate the issuer before resource SQL', async () => {
  const execution = await source('./run-execution.ts');
  for (const name of ['assertDeliveryPublicationMaintenanceExecution', 'assertDeliveryPublicationReceivedExecution',
    'assertDeliveryPublicationReconciliationExecution', 'assertDeliveryPublicationExecution']) {
    const friend = namedFunction(execution, name);
    scopedCalls(friend, 'assertSqliteConnectionOwnedBy', 1, 1);
    const guard = calls(friend, 'assertSqliteConnectionOwnedBy')[0]!;
    const resourceCall: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
          ['resources', 'assertCurrent'].includes(node.expression.name.text)) resourceCall.push(node);
      ts.forEachChild(node, visit);
    };
    visit(friend); assert.equal(resourceCall.length, 1, 'the real original task remains the sole resource owner');
    assert.equal(resourceCall[0]!.arguments[0]?.getText(), 'connection');
    assert(guard.end < resourceCall[0]!.pos, 'issuer validation precedes any original resource SQL');
    if (name !== 'assertDeliveryPublicationExecution') {
      const brands = calls(friend, 'ownedRootTask'); assert.equal(brands.length, 1);
      assert(brands[0]!.end < guard.pos, 'the original Run/execution/task/catalog brands are checked first');
    }
  }
  for (const map of ['publicationMaintenanceTasks', 'publicationReceivedTasks', 'publicationReconciliationTasks']) {
    const registered: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
          node.expression.expression.getText() === map && node.expression.name.text === 'set') registered.push(node);
      ts.forEachChild(node, visit);
    };
    visit(execution); assert.equal(registered.length, 1);
    scopedCalls(namedMethod(registered[0]!, 'resources'), 'assertActiveStateOwner', 0, 1);
  }
});

test('publication prepare, claim, maintenance and preflight retain every original check in the same scoped connection', async () => {
  const invocation = await source('./publication-invocation.ts'), preflight = await source('./publication-preflight.ts');
  const current = namedFunction(invocation, 'assertCurrent');
  scopedCalls(current, 'assertDeliveryPublicationExecution', 5, 1);
  scopedCalls(current, 'assertDeliveryPublicationMaintenanceExecution', 5, 1);
  scopedCalls(current, 'assertActiveStateOwner', 0, 1);
  for (const [name, check, index] of [
    ['preparePublicationInvocation', 'assertDeliveryPublicationExecution', 5],
    ['preparePublicationMaintenance', 'assertDeliveryPublicationMaintenanceExecution', 5]
  ] as const) {
    const cut = namedVariable(namedFunction(invocation, name), 'assertCut');
    scopedCalls(cut, 'assertSqliteConnectionOwnedBy', 1, 1);
    scopedCalls(cut, 'assertActiveStateOwner', 0, 1); scopedCalls(cut, check, index, 1);
    scopedCalls(cut, 'sqlCut', 0, 1);
  }
  const claim = namedMethod(namedFunction(invocation, 'assertPublicationClaimForInvocation'), 'validate');
  scopedCalls(claim, 'assertCurrent', 1, 1); scopedCalls(claim, 'assertPublicationPreflight', 3, 1);
  const prepare = namedFunction(preflight, 'preparePublicationPreflight'), cut = namedVariable(prepare, 'assertCut');
  scopedCalls(cut, 'assertActiveStateOwner', 0, 1); scopedCalls(cut, 'publicationCut', 0, 1);
  scopedCalls(cut, 'readRun', 0, 1); scopedCalls(cut, 'readSession', 0, 1);
  scopedCalls(cut, 'readSessionPrincipalId', 0, 1); scopedCalls(cut, 'assertExecution', 0, 1);
  const fresh = namedVariable(prepare, 'assertCurrent');
  scopedCalls(fresh, 'assertCut', 0, 1); scopedCalls(fresh, 'readTimeFence', 0, 1);
  scopedCalls(namedVariable(prepare, 'assertExecution'), 'assertDeliveryPublicationExecution', 5, 1);
  scopedCalls(namedFunction(preflight, 'assertPublicationPreflight'), 'assertSqliteConnectionOwnedBy', 1, 1);
});

test('publication reconciliation and received-result terminal writers propagate the same SQL scope through their original brands', async () => {
  const reconciliation = await source('./publication-reconciliation.ts');
  let scopedTransactions = 0;
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText() === 'driver' && node.expression.name.text === 'transaction') {
      const check = calls(node, 'assertDeliveryPublicationReconciliationExecution');
      for (const call of check) {
        assert.equal(call.arguments[5]?.getText(), 'connection', 'the original resource assertion uses the genuine commit scope');
        scopedTransactions++;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(reconciliation); assert.equal(scopedTransactions, 2, 'both original publication wait/dispatch transactions retain resource checks');
  const finalization = await source('./publication-finalization.ts'), settlement = await source('./publication-settlement.ts');
  scopedCalls(namedFunction(finalization, 'originalReceived'), 'assertDeliveryPublicationReceivedExecution', 5, 1);
  scopedCalls(namedFunction(finalization, 'readOwnedPublicationReceivedResult'), 'originalReceived', 5, 1);
  scopedCalls(namedFunction(finalization, 'original'), 'originalReceived', 5, 1);
  for (const name of ['validateOwnedPublicationFinalization', 'commitOwnedPublicationFinalization', 'assertOwnedPublicationTerminalSql'])
    scopedCalls(namedFunction(finalization, name), 'original', 3, 1);
  scopedCalls(namedFunction(settlement, 'originalReceived'), 'readOwnedPublicationReceivedResult', 5, 1);
  const recovery = namedFunction(settlement, 'assertPublicationReconciliationSettlementForInvocation');
  scopedCalls(recovery, 'assertSqliteConnectionOwnedBy', 1, 1); scopedCalls(recovery, 'originalReceived', 1, 1);
  scopedCalls(namedMethod(namedFunction(settlement, 'selectReceived'), 'assertCut'), 'originalReceived', 1, 1);
  const reducer = namedFunction(await source('./reducers/invocation.ts'), 'preparePublicationReconciliationInvocationSettlement');
  const claims = calls(reducer, 'assertPublicationReconciliationSettlementForInvocation');
  assert.equal(claims.length, 2, 'the original binding is checked before preparation and again inside the real transaction');
  assert.equal(claims[0]!.arguments.length, 3); assert.equal(claims[1]!.arguments[3]?.getText(), 'connection');
});

test('original publication handoff and both settlement branches pass their commit scope through completion history', async () => {
  const invocation = await source('./publication-invocation.ts'), finalization = await source('./publication-finalization.ts');
  scopedCalls(namedFunction(invocation, 'readOwnedPublicationCompletion'), 'claimedBinding', 4, 1);
  scopedCalls(namedFunction(invocation, 'readOwnedPublicationCompletion'), 'assertOwnedPublicationPath', 4, 1);
  scopedCalls(namedFunction(invocation, 'assertOwnedPublicationPath'), 'claimedBinding', 4, 1);
  scopedCalls(namedFunction(invocation, 'assertOwnedPublicationPath'), 'assertActiveStateOwner', 0, 1);
  scopedCalls(namedFunction(invocation, 'claimedBinding'), 'assertSqliteConnectionOwnedBy', 1, 1);
  scopedCalls(namedFunction(invocation, 'readOwnedPublicationPreparationClosure'), 'assertUnclaimedPreparation', 1, 1);
  scopedCalls(namedFunction(invocation, 'assertUnclaimedPreparation'), 'assertSqliteConnectionOwnedBy', 1, 1);
  const handoff = namedFunction(finalization, 'handoffOwnedPublicationResult');
  const completions = calls(handoff, 'readOwnedPublicationCompletion');
  assert.equal(completions.length, 2, 'the original is read before I/O and revalidated inside the actual commit');
  assert.equal(completions[0]!.arguments[4]?.getText(), 'driver', 'the original nontransactional read explicitly uses its driver');
  assert.equal(completions[1]!.arguments[4]?.getText(), 'connection', 'the committed handoff reuses its actual transaction');
  const settlement = await source('./publication-settlement.ts');
  scopedCalls(namedFunction(settlement, 'original'), 'readOwnedPublicationCompletion', 4, 1);
  scopedCalls(namedVariable(namedFunction(settlement, 'select'), 'assertCut'), 'original', 1, 1);
  scopedCalls(namedFunction(settlement, 'originalPreparation'), 'readOwnedPublicationPreparationClosure', 4, 1);
  scopedCalls(namedMethod(namedFunction(settlement, 'selectPreparation'), 'assertCut'), 'originalPreparation', 1, 1);
});

test('initial ambiguity and abort terminal callbacks preserve the same scope through every original resource check', async () => {
  const invocation = await source('./publication-invocation.ts');
  scopedCalls(namedFunction(invocation, 'originalInitialAmbiguity'), 'assertSqliteConnectionOwnedBy', 1, 1);
  scopedCalls(namedFunction(invocation, 'assertOwnedPublicationInitialAmbiguitySql'), 'originalInitialAmbiguity', 4, 1);
  const abort = await source('./publication-abort-finalization.ts');
  scopedCalls(namedFunction(abort, 'original'), 'assertDeliveryPublicationMaintenanceExecution', 5, 1);
  for (const name of ['metadata', 'validate', 'commit', 'assertFresh'])
    scopedCalls(namedMethod(namedFunction(abort, 'readOwnedPublicationAbortFinalization'), name), 'original', 3, 1);
  const stop = await source('./reducers/stop.ts');
  const members: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText() === 'publication' && ['metadata', 'assertFresh'].includes(node.expression.name.text)) members.push(node);
    ts.forEachChild(node, visit);
  };
  visit(stop); assert.equal(members.length, 2, 'both original late terminal callbacks retain explicit scope');
  for (const member of members) assert.equal(member.arguments.at(-1)?.getText(), 'connection',
    'the original Stop transaction, not an outer driver or structural callback, owns the SQL scope');
});

test('completion SQL helpers cannot silently fall back to an outer driver at a new call site', async () => {
  const specifications = [
    ['./publication-invocation.ts', ['claimedBinding', 'assertUnclaimedPreparation', 'assertOwnedPublicationPath',
      'readOwnedPublicationCompletion', 'readOwnedPublicationPreparationClosure', 'originalInitialAmbiguity']],
    ['./publication-settlement.ts', ['original', 'originalPreparation']],
    ['./publication-abort-finalization.ts', ['original']]
  ] as const;
  for (const [file, helpers] of specifications) {
    const root = await source(file);
    for (const name of helpers) {
      const helper = namedFunction(root, name), parameter = helper.parameters.at(-1)!;
      assert.equal(parameter.name.getText(), 'connection', 'each SQL-capable helper makes its receiver explicit');
      assert.equal(parameter.initializer, undefined, 'no implicit outer-driver fallback is permitted');
      assert.equal(parameter.questionToken, undefined, 'the owning scope is mandatory');
      for (const call of calls(root, name)) {
        assert.equal(call.arguments.length, helper.parameters.length, 'every real in-module caller chooses its receiver');
        assert(['driver', 'binding.driver', 'connection'].includes(call.arguments.at(-1)!.getText()),
          'a SQL receiver is the genuine driver or scoped connection, not a caller callback');
      }
    }
  }
});
