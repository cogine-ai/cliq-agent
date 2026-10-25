import assert from 'node:assert/strict';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';
import { advanceTimeFence, insertGenesisTimeFence, readTimeFence, recoverRegressedTimeFence } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { applyKernelSchema } from './schema.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';

async function actualClockCut(name: 'source-git-owner.ts' | 'source-git-rules.ts', driver: SqliteDriver): Promise<(action: () => void) => void> {
  const text = await readFile(new URL(name, import.meta.url), 'utf8');
  const source = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const matches: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node) => { if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'cut') matches.push(node);
    ts.forEachChild(node, visit); }; visit(source); assert.equal(matches.length, 1);
  const code = ts.transpileModule(`const ${matches[0]!.getText(source)};`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  }).outputText;
  const row = { rowDigest: 'original-row', phase: 'active', cancelRequested: false, deadlineAt: '2026-10-25T13:00:00.000Z', principalId: 'principal' };
  const deps = { driver, signal: new AbortController().signal,
    // This existing actual-function-body data seam isolates transaction/time
    // behavior. These inert prerequisites are not a StateOwner, target, grant
    // or native capability, and cannot enter either production factory.
    assertVerifiedSourceInspectionTargetCut() {}, controlledHome: { assertHeld() {} }, owner: { ownerEpoch: 1 }, target: {}, key: {},
    state: { row }, readSourceInspectionAttempt: () => row, advanceTimeFence, readTimeFence,
    consent: { expiresAt: row.deadlineAt }, original: { inspectionGrantId: 'grant', inspectionReceiptRef: 'receipt', ignoreReadConsents: [] },
    readAuthorizationGrant: () => ({ state: 'consumed', consumptionReceiptRef: 'receipt', ownerPrincipalId: 'principal', expiresAt: row.deadlineAt }),
    invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }, KernelStorageError };
  const cut = new Function(...Object.keys(deps), `${code}\nreturn cut;`)(...Object.values(deps));
  return name === 'source-git-owner.ts' ? action => cut(action) : action => cut(undefined, action);
}

for (const name of ['source-git-owner.ts', 'source-git-rules.ts'] as const)
  test(`${name} commits a real regressed SQL fence before refusal and cannot auto-heal at the old high-water`, async t => {
    const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-git-clock-'));
    const driver = openSqliteDriver(path.join(directory, 'kernel.sqlite3'));
    try {
      applyKernelSchema(driver);
      driver.transaction(connection => insertGenesisTimeFence(connection, 1, '2026-10-25T12:00:00.000Z'));
      let now = Date.parse('2026-10-25T11:59:59.999Z'), actions = 0;
      t.mock.method(Date, 'now', () => now);
      const cut = await actualClockCut(name, driver), action = () => { actions++; };
      assert.throws(() => cut(action), { code: 'RECOVERY_REQUIRED' });
      assert.equal(actions, 0); assert.equal(readTimeFence(driver)?.state, 'clock_regressed');
      assert.equal(readTimeFence(driver)?.lastAcceptedAt, '2026-10-25T12:00:00.000Z');
      assert.equal(readTimeFence(driver)?.observedWallClockAt, '2026-10-25T11:59:59.999Z');
      now = Date.parse('2026-10-25T12:00:00.001Z');
      assert.throws(() => cut(action), { code: 'RECOVERY_REQUIRED' });
      assert.equal(actions, 0); assert.equal(readTimeFence(driver)?.state, 'clock_regressed');
      driver.transaction(connection => assert.equal(recoverRegressedTimeFence(connection, 1), 'healthy'));
      cut(action); assert.equal(actions, 1); assert.equal(readTimeFence(driver)?.state, 'healthy');
    } finally { t.mock.restoreAll(); driver.close(); await rm(directory, { recursive: true, force: true }); }
  });
