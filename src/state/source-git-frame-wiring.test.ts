import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';

const source = async (name: string) => ts.createSourceFile(name, await readFile(new URL(name, import.meta.url), 'utf8'),
  ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
function calls(node: ts.Node, name: string): ts.CallExpression[] {
  const result: ts.CallExpression[] = [];
  const visit = (current: ts.Node) => {
    if (ts.isCallExpression(current) && ts.isIdentifier(current.expression) && current.expression.text === name) result.push(current);
    ts.forEachChild(current, visit);
  }; visit(node); return result;
}

test('source capture preserves the original authenticated frame through data snapshots to its synchronous cut', async () => {
  // Mechanical routing only: these source statements do not mint a frame,
  // native owner, grant, Run, or physical qualification.
  const store = await source('./store.ts'), owner = await source('./source-inspection-owner.ts'), target = await source('./source-target.ts');
  const storeCall = calls(store, 'captureSubmittedSource');
  assert.equal(storeCall.length, 1);
  const input = storeCall[0]!.arguments[4];
  assert(input && ts.isObjectLiteralExpression(input));
  assert(input.properties.some(property => ts.isPropertyAssignment(property) && property.name.getText(store) === 'identity' &&
    property.initializer.getText(store) === 'frameIdentity'), 'snapshot data must not replace the original current-frame reference');
  const targetCalls = calls(owner, 'createVerifiedSourceInspectionTarget');
  assert.equal(targetCalls.length, 1);
  assert.equal(targetCalls[0]!.arguments[2]?.getText(owner), 'input.identity');
  const cut = target.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'assertVerifiedSourceInspectionTargetCut');
  assert(cut && ts.isFunctionDeclaration(cut) && cut.body);
  const current = calls(cut, 'assertCurrentControlFrame');
  assert.equal(current.length, 1);
  assert.equal(current[0]!.arguments[1]?.getText(target), 'held.frameIdentity');
  assert(current[0]!.pos < calls(cut, 'readSession')[0]!.pos, 'actual frame is checked inside the final SQL cut, before accepting Session data');
  const producer = target.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'createVerifiedSourceInspectionTarget');
  assert(producer && ts.isFunctionDeclaration(producer) && producer.body);
  assert.match(producer.getText(target), /const frameIdentity = identity;/u);
  assert.match(producer.getText(target), /channel\.channel\.transport\.kind === 'uds_peer' \? \{ frameIdentity \} : \{\}/u);
});
