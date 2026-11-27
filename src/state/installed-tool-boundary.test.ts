// Exercise the actual scheduler statements with inert scheduling outcomes.
// These callbacks cannot create a lease, Run, native owner or recovery proof;
// installed Linux qualification independently exercises the physical owner.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';

async function boundary() {
  const source = ts.createSourceFile('store.ts', await readFile(new URL('./store.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const matches: ts.Block[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isBlock(node) && node.statements.some(statement => ts.isVariableStatement(statement) &&
        statement.declarationList.declarations.some(value => value.name.getText(source) === 'toolExecution'))) matches.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(matches.length, 1);
  const statements = matches[0]!.statements;
  const start = statements.findIndex(statement => ts.isVariableStatement(statement) &&
    statement.declarationList.declarations.some(value => value.name.getText(source) === 'toolExecution'));
  const code = ts.transpileModule(`return async function () { for (let turn=0;turn<1;turn++) {
    ${statements.slice(start).map(statement => statement.getText(source)).join('\n')}
  } };`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  return (renew: () => string, execute: () => Promise<{ revision: number }>, recover: (...args: unknown[]) => Promise<void>) =>
    new Function('nativeExecution', 'beginWorkerRecovery', 'current', 'runId', code)(
      async () => ({ renewCurrentWorkerLease: renew, executeCurrentTool: execute }), recover, { revision: 7 }, 'original-run') as () => Promise<void>;
}

test('continuous tool scheduling renews through the existing guard before entering a new operation', async () => {
  const build = await boundary();
  for (const outcome of ['inactive', 'unchanged', 'renewed']) {
    const order: string[] = [];
    await build(() => { order.push('guard'); return outcome; }, async () => { order.push('execute'); return { revision: 8 }; },
      async () => { assert.fail('a live or absent worker must not be declared expired'); })();
    assert.deepEqual(order, ['guard', 'execute']);
  }
});

test('an expired worker goes to original recovery without preparing another tool', async () => {
  const build = await boundary(), receiver = { driver: {}, artifacts: {}, owner: {} }, order: string[] = [];
  await build(() => { order.push('expired'); return 'expired'; }, async () => { assert.fail('expired worker dispatched'); },
    async (...args) => { order.push('recover'); assert.deepEqual(args, [receiver.driver, receiver.artifacts, receiver.owner,
      { runId: 'original-run', expectedRunRevision: 7 }]); }).call(receiver);
  assert.deepEqual(order, ['expired', 'recover']);
  const failure = Error('original physical owner refused');
  await assert.rejects(build(() => { throw failure; }, async () => { assert.fail('failed guard dispatched'); },
    async () => { assert.fail('failed guard invented an expiry'); })(), error => error === failure);
});
