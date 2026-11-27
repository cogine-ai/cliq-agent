// Test the owned HTTP fixture's consumed recipe and immutable workload wiring.
// These checks do not mint native authority or qualify an installed lifecycle.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';

const text = readFileSync(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
const source = ts.createSourceFile('journey.ts', text, ts.ScriptTarget.Latest, true);
const nodes = [];
const collect = node => { nodes.push(node); ts.forEachChild(node, collect); }; collect(source);
const callNamed = (node, name) => ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name;

test('the independent source-limit responder owns exactly edit/end for each of its two actual Runs', () => {
  const declaration = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'finalSourceLimitTurn');
  assert(declaration, 'the independent workload must consume its own fixed four-turn recipe');
  const script = ts.transpileModule(declaration.getText(source) + '\nglobalThis.turn = finalSourceLimitTurn;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const context = { assert }; vm.runInNewContext(script, context);
  assert.deepEqual(JSON.parse(JSON.stringify([1, 2, 3, 4].map(context.turn))), [
    { limitKind: 'changed_paths', editReply: true }, { limitKind: 'changed_paths', editReply: false },
    { limitKind: 'changed_bytes', editReply: true }, { limitKind: 'changed_bytes', editReply: false }
  ]);
  for (const invalid of [0, 5, -1, 1.5, NaN, Infinity]) assert.throws(() => context.turn(invalid));
});

test('the source-limit workload enters the existing fresh-install harness as a mandatory independently scanned campaign', () => {
  const shell = readFileSync(new URL('../qualify-systemd-user.sh', import.meta.url), 'utf8');
  assert(/--run-final-source-limits-journey\)\s*probe_campaign_kind=run-journey;\s*probe_run_driver_mode=--final-source-limits-campaign;\s*shift\s*;;/u.test(shell),
    'the fixed mode must use the existing fresh run-journey fixture lifecycle');
  const workflow = readFileSync(new URL('../../../.github/workflows/kernel-foundation.yml', import.meta.url), 'utf8');
  const job = /  linux-installed-run:\n([\s\S]*?)(?=\n  [a-z][a-z0-9-]*:)/u.exec(workflow)?.[1]; assert(job);
  assert.match(job, /timeout-minutes:\s*20/u);
  assert(/node --test[^\n]*installed-run-partition\.test\.mjs/u.test(job), 'the workload wiring guard must run before actual installed qualification');
  assert.match(job, /qualify-systemd-user\.sh --run-journey/u);
  assert.match(job, /qualify-systemd-user\.sh --run-final-source-limits-journey/u);
  assert.match(job, /qualify-systemd-user\.sh --run-failure-journey/u);
  assert.match(job, /qualify-systemd-user\.sh --run-retry-journey/u);
  const step = /      - name: Exercise independent final-source limits[^\n]*\n([\s\S]*?)(?=      - name:)/u.exec(job)?.[1]; assert(step);
  assert.match(step, /!cancelled\(\) && steps\.build\.outcome == 'success'/u);
  assert.doesNotMatch(step, /continue-on-error|\|\| true|exit 0/u);
  const upload = /      - name: Retain independent final-source limits[^\n]*\n([\s\S]*?)(?=      - name:|$)/u.exec(job)?.[1]; assert(upload);
  assert.match(upload, /if:\s*always\(\)/u);
  assert.match(upload, /name:\s*installed-run-source-limits-/u);
  assert.match(upload, /path:\s*\$\{\{ runner\.temp \}\}\/cliq-installed-run-source-limits\/\*\.json/u);
});

test('the independent workload branches before ordinary Run dispatch and keeps the one original complete-corpus scanner', () => {
  const branch = nodes.find(node => ts.isIfStatement(node) && ts.isIdentifier(node.expression) && node.expression.text === 'sourceLimitsOnly');
  assert(branch && ts.isBlock(branch.thenStatement) && branch.elseStatement && ts.isBlock(branch.elseStatement));
  assert.equal(branch.thenStatement.statements.length, 1);
  const invocation = branch.thenStatement.statements[0];
  assert(ts.isExpressionStatement(invocation) && ts.isAwaitExpression(invocation.expression) &&
    callNamed(invocation.expression.expression, 'qualifyFinalSourceLimits'));
  const ordinary = branch.elseStatement.statements[0];
  assert(ts.isExpressionStatement(ordinary) && callNamed(ordinary.expression, 'registerSubmission'));
  assert.equal(ordinary.expression.arguments[0].getText(source), 'submit');
  const producer = nodes.find(node => ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'qualifyFinalSourceLimits');
  assert(producer && producer.initializer && ts.isArrowFunction(producer.initializer));
  assert.doesNotMatch(producer.initializer.getText(source), /reflectionEnabled|shortRunEnabled|terminalHistorySupervisor|createCredentialSecretScanner/u);
  const scanner = nodes.filter(node => callNamed(node, 'createCredentialSecretScanner'));
  assert.equal(scanner.length, 1, 'one scanner spans the entire campaign, including its final original corpus');
  const limits = vm.runInNewContext(`(${scanner[0].arguments[1].getText(source)})`);
  assert.equal(limits.maxStreams, 4096); assert.equal(limits.maxBytes, 536870912);
  const corpus = nodes.filter(node => callNamed(node, 'scanCredentialSecretCorpus')); assert.equal(corpus.length, 1);
  const input = corpus[0].arguments[0]; assert(ts.isObjectLiteralExpression(input));
  assert(input.properties.some(property => ts.isShorthandPropertyAssignment(property) && property.name.text === 'scanner'));
  assert.match(text.slice(corpus[0].pos - 200, corpus[0].pos), /installedWritersJoined[\s\S]*httpsJoined[\s\S]*daemonJoined/u);
});
