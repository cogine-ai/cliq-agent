// Execute the real journey's extracted response-handling data seam. This is
// not an installed client, StateOwner, authority, or Linux qualification.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const text = readFileSync(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
const source = ts.createSourceFile('installed-node-journey.ts', text, ts.ScriptTarget.Latest, true);
const declarations = [], deliveryCalls = [];
const visit = node => {
  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) &&
      ['recordRefusal', 'accepted'].includes(node.name.text)) declarations.push(node);
  if (ts.isCallExpression(node) && node.expression.getText(source) === 'runInstalledDeliveryCases') deliveryCalls.push(node);
  ts.forEachChild(node, visit);
};
visit(source);
assert.equal(declarations.filter(node => node.name.text === 'accepted').length, 1);
assert(declarations.filter(node => node.name.text === 'recordRefusal').length <= 1);
assert.equal(deliveryCalls.length, 1);
const context = deliveryCalls[0].arguments[0]; assert(ts.isObjectLiteralExpression(context));
const send = context.properties.filter(node => ts.isPropertyAssignment(node) && node.name.getText(source) === 'send');
assert.equal(send.length, 1); assert(ts.isArrowFunction(send[0].initializer));
const data = declarations.map(node => `const ${node.getText(source)};`).join('\n') +
  `\nconst send = ${send[0].initializer.getText(source)};\nreturn { accepted, send };`;
const build = new Function('client', 'report', 'assert', ts.transpileModule(data,
  { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText);

test('Delivery records the existing fixed refusal diagnosis while returning every real response without acceptance or retry', async () => {
  const report = {}, calls = [], queue = [];
  const handling = build({ send: async (...args) => { calls.push(args); return queue.shift(); } }, report, assert);
  const core = { protocolVersion: 1, method: 'run.apply' };
  const refusal = { protocolVersion: 1, ok: false, method: 'run.apply', error: {
    schemaVersion: 1, code: 'ARTIFACT_MISMATCH', retryable: false, messageCode: 'control.read_rejected' } };
  queue.push(refusal);
  assert.strictEqual(await handling.send(core, 30000), refusal);
  assert.deepEqual(report.lastRefusal, { method: 'run.apply', code: 'ARTIFACT_MISMATCH' });
  assert.equal(calls.length, 1); assert.strictEqual(calls[0][0], core); assert.equal(calls[0][1], 30000);

  // Deliberate refusal cases must inspect their actual response themselves.
  // Neither arbitrary exception text nor an unknown/boxed code enters output.
  for (const code of ['RUN_TERMINAL', 'do-not-retain-arbitrary-text', new String('INTERNAL')]) {
    const response = { ...refusal, error: { ...refusal.error, code, messageCode: 'do-not-retain-arbitrary-text' } };
    queue.push(response); assert.strictEqual(await handling.send({ ...core, method: 'run.cancel' }), response);
    assert.deepEqual(report.lastRefusal, { method: 'run.cancel', code: 'unclassified' });
  }
  const success = { protocolVersion: 1, ok: true, result: { method: 'run.get' } };
  const previous = report.lastRefusal; queue.push(success);
  assert.strictEqual(await handling.send({ protocolVersion: 1, method: 'run.get' }), success);
  assert.strictEqual(report.lastRefusal, previous); assert.equal(calls.length, 5);
  assert.equal(queue.length, 0); assert(calls.slice(1).every(call => call[1] === 5000));

  // The original expected-success path still asserts; diagnosis is not an
  // acceptance decision, and it does not widen the existing code whitelist.
  assert.throws(() => handling.accepted(refusal, 'run.apply'), { code: 'ERR_ASSERTION' });
  assert.deepEqual(report.lastRefusal, { method: 'run.apply', code: 'ARTIFACT_MISMATCH' });
  assert.strictEqual(handling.accepted(success, 'run.get'), success.result);
});
