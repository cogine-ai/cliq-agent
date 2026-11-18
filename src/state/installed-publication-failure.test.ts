import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Script } from 'node:vm';
import ts from 'typescript';

test('the original preparation catch records its untouched refusal before failure retirement', async () => {
  const source = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'),
    ts.ScriptTarget.Latest, true);
  const callbacks: ts.ArrowFunction[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'catch' &&
        ts.isCallExpression(node.expression.expression) &&
        node.expression.expression.expression.getText(source) === 'publication.preparePublicationInvocation') {
      const callback = node.arguments[0]; assert(callback && ts.isArrowFunction(callback)); callbacks.push(callback);
    }
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(callbacks.length, 1);
  const events: unknown[] = [], original = new Error('inert refusal');
  for (const subscribed of [false, true]) {
    const context = { closed: false, isClosing: () => false,
      preparationDiagnosis: subscribed ? { failure(error: unknown, closing: boolean) { events.push(error, closing); } } : undefined,
      observe: undefined as undefined | ((error: unknown) => never) };
    new Script(ts.transpileModule(`globalThis.observe = ${callbacks[0]!.getText(source)};`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText).runInNewContext(context);
    assert.throws(() => context.observe!(original), error => error === original);
  }
  assert.deepEqual(events, [original, false]);
});
