import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { assertSameAuthorizationListing } from './installed-client-applications.js';

// Powerless response data: no connection, StateOwner, Run, grant or native proof.
const listing = (grants: readonly unknown[], nextCursor?: string) => ({ protocolVersion: 1, ok: true,
  result: { method: 'authorization.list', grants, ...(nextCursor === undefined ? {} : { nextCursor }) } });
const original = { id: 'original', state: 'active', target: { kind: 'workspace' } };

test('the actual bounded failure projection includes the two installed application source frames', async () => {
  // Only the production regular expression and inert stack text are used;
  // this neither runs a client nor manufactures a connection or Run proof.
  const source = await readFile(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('qualifier.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const expressions: string[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isRegularExpressionLiteral(node) && node.text.includes('qualify-installed-run-journey') &&
        node.text.includes('installed-client-consumer')) expressions.push(node.text);
    ts.forEachChild(node, visit);
  };
  visit(file); assert.equal(expressions.length, 1);
  const literal = expressions[0]!, end = literal.lastIndexOf('/');
  const pattern = new RegExp(literal.slice(1, end), literal.slice(end + 1));
  const frames = [...('at /owned/installed-client-applications.ts:123:4\n' +
    'at /owned/installed-ink-consumer.ts:56:7\n').matchAll(pattern)].map(match => [match[1], Number(match[2]), Number(match[3])]);
  assert.deepEqual(frames, [['installed-client-applications', 123, 4], ['installed-ink-consumer', 56, 7]]);
  assert.deepEqual([...('at /owned/not-permitted.ts:1:1\n' +
    'at /owned/installed-ink-consumer.ts:0:1\n').matchAll(pattern)], []);
});

test('an empty original authorization listing is compared exactly without creating a grant', () => {
  assertSameAuthorizationListing(listing([]), listing([]));
});

test('a fresh opaque cursor may differ while the complete original grant page stays identical', () => {
  assertSameAuthorizationListing(listing([original], 'old-cut'), listing([original], 'new-cut'));
});

for (const [name, expected, actual] of [
  ['omitted original grant', listing([original]), listing([])],
  ['invented grant', listing([]), listing([original])],
  ['altered original grant', listing([original]), listing([{ ...original, state: 'revoked' }])],
  ['changed page completeness', listing([original], 'old-cut'), listing([original])],
  ['invalid cursor kind', listing([original], 'old-cut'), { ...listing([original]), result: { ...listing([original]).result, nextCursor: 0 } }],
  ['unmatched response field', listing([original]), { ...listing([original]), result: { ...listing([original]).result, extra: true } }],
  ['refused observation', listing([]), { protocolVersion: 1, ok: false }],
  ['wrong original response method', { ...listing([original]), result: { ...listing([original]).result, method: 'run.list' } }, listing([original])],
] as const) test(`authorization comparison rejects ${name}`, () => {
  assert.throws(() => assertSameAuthorizationListing(expected, actual));
});
