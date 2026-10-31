// Source wiring only. The real Linux timeout-retirement-failure campaign
// independently verifies the unchanged wait and retained live StateOwner.
// This test creates no task, native receipt, Run or recovery authority.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';

test('worker probe closure preserves a completed result but cannot advance through retained cleanup uncertainty', async () => {
  const source = await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  async function closeProbe(');
  const end = source.indexOf('  async function closePublicationProbe(', start);
  assert(start >= 0 && end > start);
  const body = source.slice(start, end);
  const joined = body.indexOf('const receipt = await retained.task.cancelAndJoin();');
  const resultWins = body.indexOf('if (current.waitingOnRef !== retained.run.waitingOnRef)', joined);
  const completed = body.indexOf('if (shutdown) return current;', resultWins);
  const uncertain = body.indexOf('if (cleanupFailure !== undefined) throw cleanupFailure;', completed);
  const persist = body.indexOf('const result = await closeWorkerRecoveryProbe(', completed);
  assert(joined >= 0 && resultWins > joined && completed > resultWins && uncertain > completed && persist > uncertain,
    'a genuine result wins first; otherwise existing cleanup uncertainty must refuse before durable probe closure');
  assert.match(body, /if \(error instanceof ResourceRetirementError\) cleanupFailure \?\?= error;/u,
    'only resource retirement uncertainty becomes sticky; joined publication failures remain retryable');
  assert.match(body, /if \(retained\.closure === closingProbe\) retained\.closure = undefined;/u,
    'a failed persistence keeps the original task and permits its ordinary joined receipt retry');
  assert(!/cleanupFailure\s*=(?!=)/u.test(body), 'probe retries cannot erase the original cleanup failure');
});

test('result preparation shares the retained read lifetime without changing raw completion catalogs', async () => {
  const store = ts.createSourceFile('store.ts', await readFile(new URL('./store.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const agent = ts.createSourceFile('agent.ts', await readFile(new URL('./reducers/agent.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const execution = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const matches = <T extends ts.Node>(root: ts.Node, predicate: (node: ts.Node) => node is T): T[] => {
    const found: T[] = [];
    const visit = (node: ts.Node) => { if (predicate(node)) found.push(node); ts.forEachChild(node, visit); };
    visit(root); return found;
  };
  const call = (root: ts.Node, name: string) => {
    const found = matches(root, (node): node is ts.CallExpression => ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name);
    assert.equal(found.length, 1); return found[0]!;
  };
  const retained = matches(store, (node): node is ts.MethodDeclaration => ts.isMethodDeclaration(node) && node.name.getText(store) === 'retainInstalledAgent');
  assert.equal(retained.length, 1);
  const loading = call(retained[0]!, 'loadAgentRun');
  assert.equal(loading.arguments[1]!.getText(store), 'this.artifacts');
  assert.equal(loading.arguments[8]?.getText(store), 'readerSignal');
  assert.match(retained[0]!.getText(store), /const readerSignal = AbortSignal\.any\(\[signal, readAbort\.signal\]\);/u);
  const result = call(agent, 'loadRunResult');
  assert.equal(result.arguments[1]!.getText(agent), 'artifacts');
  assert.equal(result.arguments[5]?.getText(agent), 'resultPreparationSignal');
  for (const name of ['loadToolContinuation', 'loadRunContinuation', 'loadFinalCandidate']) {
    const original = call(agent, name);
    assert.equal(original.arguments[1]!.getText(agent), 'artifacts');
    assert(!original.arguments.some(value => value.getText(agent).includes('resultPreparationSignal')));
  }
  const physical = call(execution, 'loadAgentRun');
  assert.equal(physical.arguments[1]!.getText(execution), 'artifacts');
  assert.equal(physical.arguments.length, 7, 'the original physical result owner keeps its independently joined raw catalog');
});


test('final admission diagnoses only the actual held callback and awaited durable result before the original scope joins', async () => {
  const source = ts.createSourceFile('store.ts', await readFile(new URL('./store.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const admissions: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'admission' && node.initializer &&
        ts.isCallExpression(node.initializer) && node.initializer.expression.getText(source) === 'withCredentialAuthorityLock') admissions.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(admissions.length, 1);
  const call = admissions[0]!.initializer as ts.CallExpression, callback = call.arguments[1]!;
  assert(ts.isArrowFunction(callback) && ts.isBlock(callback.body));
  const body = callback.body, text = body.getText(source);
  assert.equal(body.statements[0]!.getText(source), "diagnosis?.stage('submit_final_admission_scope_held');");
  const durable = body.statements.find((node): node is ts.VariableStatement => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(declaration => declaration.initializer && ts.isAwaitExpression(declaration.initializer) &&
      ts.isCallExpression(declaration.initializer.expression) && declaration.initializer.expression.expression.getText(source) === 'admitInstalledRun'));
  assert(durable, 'committed must follow the original awaited admission, not just creation of its Promise');
  const held = text.indexOf("diagnosis?.stage('submit_final_admission_scope_held');"), admission = text.indexOf(durable.getText(source));
  const committed = text.indexOf("diagnosis?.stage('submit_final_admission_committed');"), returned = text.indexOf('return admitted;');
  assert(held < text.indexOf('signal.throwIfAborted();') && admission > held && committed > admission && returned > committed);
  assert.match(text, /assertCurrentControlFrame\(this\.owner, identity\); token\.assertHeld\(\);/u);
  assert(!text.includes('submit_postcommit_load'), 'postcommit load remains outside the held callback and original scope join');
  const start = admissions[0]!.pos, outer = source.getText().slice(start);
  assert(outer.indexOf('const result = await admission;') < outer.indexOf("diagnosis?.stage('submit_postcommit_load');"));
});
