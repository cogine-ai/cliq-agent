// Source-wiring data only. The existing artifact-read-pool and cas-verify
// suites separately exercise real CAS handles, cancellation and retirement.
// No Run, StateOwner, native evidence or Linux qualification is constructed.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';

const groups = [
  ['recovery-closure.ts', 'artifacts', ['[...unique]']],
  ['run-authority.ts', 'openingReads', ['manifest.entries']],
  ['resource-stop.ts', 'artifacts', ['manifest.entries', 'sourceItems', 'cut.items']],
  ['tool-cut.ts', 'artifacts', ['closure.items']],
  ['agent-context.ts', 'artifacts', ['turn.toolCalls', 'workspace.entries']],
  ['stop-recovery.ts', 'artifacts', ['closure.items']],
  ['worker-recovery.ts', 'artifacts', ['open']]
] as const;

for (const [file, catalog, lists] of groups) test(`${file} dispatches each retained read group lazily through its original catalog`, async () => {
  const source = await readFile(new URL(`./${file}`, import.meta.url), 'utf8');
  const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true), calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText(parsed);
      assert.notEqual(callee, 'Promise.all', `${file}: no fail-fast read group may release issued siblings`);
      if (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'mapReads') {
        assert.equal(callee, `${catalog}.mapReads`, `${file}: retain the original read lifetime, not a fresh or raw catalog`);
        calls.push(node);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed);
  assert.deepEqual(calls.map(call => call.arguments[0]?.getText(parsed)), lists,
    `${file}: every original variable-length CAS group must use the same bounded resource-joining module`);
  for (const call of calls) {
    assert.equal(call.arguments.length, 2, `${file}: the catalog owns dispatch and joining`);
    assert(ts.isArrowFunction(call.arguments[1]!), `${file}: pass an unstarted callback, never an array of issued reads`);
  }
  const eager: string[] = [];
  const checkEager = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'joinResourceOperations') eager.push(node.getText(parsed));
    ts.forEachChild(node, checkEager);
  };
  checkEager(parsed);
  if (file === 'resource-stop.ts') {
    assert.equal(eager.length, 1, 'retain only the original fixed three-item compaction-envelope group');
    assert.match(eager[0]!, /^joinResourceOperations\(\[\s*envelope\.systemInstructionRef, envelope\.userPrefixRef, envelope\.userSuffixRef\s*\]\.map\(ref => readCanonicalArtifact<ModelTextV1>\(artifacts, ref\)\)\)$/u);
  } else assert.deepEqual(eager, [], `${file}: variable groups must not eagerly start every read before dispatch can stop`);
});
