// Source/publisher identity and fixture wiring only. No installation,
// StateOwner, Run, native authority or qualification result is constructed.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';
import { effectiveSourceExcludes } from '../../../src/kernel/dependency-source.js';

test('the callback qualifier candidate pin names the complete current native image while preserving its original baseline and evidence reader', async () => {
  const source = await readFile(new URL('./qualify-native-callback-lifecycle.ts', import.meta.url), 'utf8');
  const native = await readFile(new URL('../../../native/linux/credential-platform.c', import.meta.url));
  const match = /const candidateNative = '([0-9a-f]{64})';/u.exec(source); assert(match);
  assert.equal(match[1], createHash('sha256').update(native).digest('hex'));
  assert.match(source, /commit: 'ba804a59dcadee80cb41c822e2d0e32198462f20'/u);
  assert.match(source, /native: '73cd16a6f23e9054c7a0b50ec6c1dcdeb47a1561f180f661686e1a63f74140a9'/u);
  assert.match(source, /readNativeCallbackEvidence\(\{ mode: view\.record\.name, stdout: run\.stdout, stderr: run\.stderr,/u);
  assert.match(source, /report\.qualified = report\.views\.every\(\(view: Record<string, any>\) => view\.evidence && !view\.evidenceRefused\)/u);
});

test('the durable source-refusal campaign keeps the original selector preflight and real owned projection refusal', async () => {
  const source = await readFile(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('installed-source-refusal.ts', source, ts.ScriptTarget.Latest, true);
  const declarations = new Map<string, ts.VariableDeclaration>();
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) declarations.set(node.name.text, node);
    if (ts.isCallExpression(node)) calls.push(node);
    ts.forEachChild(node, visit);
  }; visit(file);
  const refusal = declarations.get('refusalCore')?.initializer; assert(refusal && ts.isObjectLiteralExpression(refusal));
  const exclude = refusal.properties.find((property): property is ts.PropertyAssignment => ts.isPropertyAssignment(property) &&
    property.name.getText(file) === 'sourceExcludes')?.initializer;
  assert(exclude && ts.isPropertyAccessExpression(exclude));
  assert.equal(exclude.getText(file), 'resourceCore.sourceExcludes');
  // The actual failure-mode submit keeps its original vendor-only exclusion;
  // its pre-existing nested .git must not choose an unrelated native refusal.
  const submit = declarations.get('submit')?.initializer;
  assert(submit && ts.isCallExpression(submit));
  const core = submit.arguments[0]; assert(core && ts.isObjectLiteralExpression(core));
  const originalExcludes = core.properties.find((property): property is ts.PropertyAssignment => ts.isPropertyAssignment(property) &&
    property.name.getText(file) === 'sourceExcludes')?.initializer;
  assert(originalExcludes && ts.isConditionalExpression(originalExcludes));
  assert.equal(originalExcludes.condition.getText(file), 'failureOnly');
  assert(ts.isArrayLiteralExpression(originalExcludes.whenTrue));
  const selectors = originalExcludes.whenTrue.elements.map(item => {
    assert(ts.isObjectLiteralExpression(item));
    const fields = Object.fromEntries(item.properties.map(property => {
      assert(ts.isPropertyAssignment(property) && ts.isStringLiteral(property.initializer));
      return [property.name.getText(file), property.initializer.text];
    }));
    assert.deepEqual(Object.keys(fields).sort(), ['path', 'scope']);
    assert(fields.scope === 'entry' || fields.scope === 'subtree');
    return { path: fields.path!, scope: fields.scope as 'entry' | 'subtree' };
  });
  assert.doesNotThrow(() => effectiveSourceExcludes({ dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: selectors }));
  assert.deepEqual(selectors, [{ path: 'vendor', scope: 'subtree' }]);
  const fixture = calls.filter(call => call.expression.getText(file) === 'withInstalledSourceRefusalFixture');
  assert.equal(fixture.length, 1);
  assert.equal(fixture[0]!.arguments[0]?.getText(file), '{ workspace: recipe.workspace, uid: ledger.uid, gid: ledger.gid }');
  assert(fixture[0]!.pos < refusal.pos && fixture[0]!.end > refusal.end);
  assert.match(source, /sourceRule: 'non_nfc_source_name'/u);
  for (const original of [
    "original nonce must replay its durable source refusal despite current credential revocation",
    "fresh nonce must bind the same original source refusal without reauthorizing capture",
    "source_changed_or_unsupported",
  ]) assert(source.includes(original));
});
