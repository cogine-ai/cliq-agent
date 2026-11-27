// Execute the actual constructor routing block with inert reader callbacks.
// This tests delegation, not a StateOwner, permission proof or installed Run.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';

async function openingRoute() {
  const source = ts.createSourceFile('tool.ts', await readFile(new URL('./reducers/tool.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const declaration = source.statements.filter(ts.isFunctionDeclaration).find(node => node.name?.text === 'loadToolContinuation');
  assert(declaration?.body);
  const blocks = declaration.body.statements.filter(ts.isIfStatement).filter(node =>
    node.expression.getText(source) === "admittedRun.waitingReason === 'approval' && admittedRun.waitingOnRef");
  assert.equal(blocks.length, 1);
  const code = ts.transpileModule(blocks[0]!.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  return new Function('admittedRun', 'openingReads', 'readCanonicalArtifact', 'cut', 'waitProof', 'requestFor', 'requireEqual',
    `return (async () => { ${code} })();`) as (...args: unknown[]) => Promise<void>;
}

test('tool construction routes only tool-owned waits to a tool cut after complete history validation', async () => {
  const route = await openingRoute(), reads = {}, run = { waitingReason: 'approval', waitingOnRef: 'inert-wait' };
  for (const kind of ['verifier_launch', 'child_merge', 'dependency_install_scripts', 'tool_call', 'mcp_server_launch']) {
    const calls: string[] = [], selected = {}, request = {};
    await route(run, reads, async (reader: unknown, ref: unknown) => {
      assert.equal(reader, reads); assert.equal(ref, run.waitingOnRef); calls.push('subject'); return { subject: { kind } };
    }, async (revision: unknown, reader: unknown) => {
      assert.equal(revision, undefined); assert.equal(reader, reads); calls.push('cut'); return selected;
    }, async (ref: unknown, reader: unknown) => {
      assert.equal(ref, run.waitingOnRef); assert.equal(reader, reads); calls.push('proof'); return { request };
    }, (cut: unknown) => { assert.equal(cut, selected); return { request }; },
    (actual: unknown, expected: unknown) => { assert.equal(actual, expected); calls.push('equal'); });
    assert.deepEqual(calls, kind === 'tool_call' ? ['subject', 'cut', 'proof', 'equal']
      : kind === 'mcp_server_launch' ? ['subject', 'cut'] : ['subject'], kind);
  }
  for (const subject of [undefined, {}, { kind: 'unknown' }]) {
    let cut = false;
    await assert.rejects(route(run, reads, async () => ({ subject }), async () => { cut = true; }));
    assert.equal(cut, false, 'unknown waits must not reach a tool or gain a fallback');
  }
  const failure = Error('original reader failed');
  await assert.rejects(route(run, reads, async () => { throw failure; }), error => error === failure);
  for (const kind of ['tool_call', 'mcp_server_launch'])
    await assert.rejects(route(run, reads, async () => ({ subject: { kind } }), async () => { throw failure; }), error => error === failure);
  await assert.rejects(route(run, reads, async () => ({ subject: { kind: 'tool_call' } }), async () => ({}),
    async () => { throw failure; }), error => error === failure);
});
