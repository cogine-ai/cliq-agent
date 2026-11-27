// Source/report transport wiring only; this test is no native qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

test('every fixed native guest campaign report is retained by the bounded artifact step', async () => {
  const source = ts.createSourceFile('run-linux-guest-verifier-campaign.ts',
    await readFile(new URL('../run-linux-guest-verifier-campaign.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const produced = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'writeFile') {
      const target = node.arguments[0];
      if (target && ts.isCallExpression(target) && ts.isPropertyAccessExpression(target.expression) &&
          target.expression.expression.getText(source) === 'path' && target.expression.name.text === 'join' &&
          target.arguments[0]?.getText(source) === 'reportRoot') {
        assert.equal(target.arguments.length, 2);
        const name = target.arguments[1]; assert(name && ts.isStringLiteral(name));
        assert.match(name.text, /^guest-[a-z-]+\.json$/u); produced.add(name.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  assert.deepEqual([...produced].sort(), ['guest-campaign-failure.json', 'guest-extractor-report.json',
    'guest-preparing-git-report.json', 'guest-verifier-report.json']);
  const workflow = await readFile(new URL('../../../.github/workflows/kernel-foundation.yml', import.meta.url), 'utf8');
  const steps = [...workflow.matchAll(/name: native-guest-verifier-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}\n\s+path: \|\n([\s\S]*?)\s+if-no-files-found:/gu)];
  assert.equal(steps.length, 1);
  const paths = steps[0]![1]!.trim().split('\n').map(line => line.trim());
  assert.equal(paths.length, new Set(paths).size);
  assert.deepEqual(paths.sort(), [...produced].sort().map(name => '${{ steps.guest.outputs.report_root }}/' + name));
  assert(paths.every(name => !name.includes('*')), 'only the original bounded JSON reports may leave the runner');
});
