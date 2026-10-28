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

test('the durable source-refusal campaign passes the original selector preflight and creates an actual nested Git object before capture', async () => {
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
  assert(exclude && ts.isArrayLiteralExpression(exclude));
  const selectors = exclude.elements.map(item => {
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
  assert.equal(selectors.length, 0);
  const root = declarations.get('refusalNestedRoot')?.initializer, nested = declarations.get('refusalNestedGit')?.initializer;
  assert(root && root.getText(file) === "path.join(recipe.workspace, 'unsupported-source-refusal')");
  assert(nested && nested.getText(file) === "path.join(refusalNestedRoot, '.git')");
  for (const name of ['refusalNestedRoot', 'refusalNestedGit']) {
    const mkdir = calls.filter(call => call.expression.getText(file) === 'mkdir' && call.arguments[0]?.getText(file) === name);
    const chown = calls.filter(call => call.expression.getText(file) === 'chown' && call.arguments[0]?.getText(file) === name);
    assert.equal(mkdir.length, 1); assert.equal(chown.length, 1);
    assert.equal(chown[0]!.arguments[1]?.getText(file), 'ledger.uid'); assert.equal(chown[0]!.arguments[2]?.getText(file), 'ledger.gid');
    assert(mkdir[0]!.pos < chown[0]!.pos && chown[0]!.end < refusal.pos);
  }
  assert.match(source, /sourceRule: 'nested_git_metadata'/u);
  for (const original of [
    "original nonce must replay its durable source refusal despite current credential revocation",
    "fresh nonce must bind the same original source refusal without reauthorizing capture",
    "source_changed_or_unsupported",
  ]) assert(source.includes(original));
});
