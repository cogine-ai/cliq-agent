import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Script } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
import { INSTALLED_CONTROL_FEATURES } from '../kernel/control-wire.js';
import { openInstalledControlTransport } from './installed-control-transport.js';
import type { HeldInstalledRuntime } from './installed-runtime.js';
import { openInstalledSupervisorClient } from './installed-control-client.js';
import { openInstalledControlSession } from '../control/session.js';

test('shared installed transport refuses structural selections before reading supplied properties', async () => {
  let accessed = false;
  const supplied = new Proxy({}, { get() { accessed = true; throw new Error('caller data was inspected'); } });
  await assert.rejects(openInstalledControlTransport(supplied as HeldInstalledRuntime, 'control'));
  assert.equal(accessed, false);
  await assert.rejects(openInstalledSupervisorClient(supplied as HeldInstalledRuntime));
  assert.equal(accessed, false);
  await assert.rejects(openInstalledSupervisorClient(supplied as HeldInstalledRuntime, 3));
  assert.equal(accessed, false);
  await assert.rejects(openInstalledControlSession(supplied as HeldInstalledRuntime));
  assert.equal(accessed, false);
});

test('the original response timer gives only apply its explicit finite admission budget', async () => {
  const source = await readFile(new URL('./installed-control-transport.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('transport.ts', source, ts.ScriptTarget.Latest, true);
  const declarations = new Map<string, ts.VariableDeclaration>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ['responseTimeoutMs', 'awaitFrame'].includes(node.name.getText(parsed)))
      declarations.set(node.name.getText(parsed), node);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(declarations.size, 2);
  for (const method of ['control.hello', ...INSTALLED_CONTROL_FEATURES]) {
    const timers: number[] = [];
    const context = { request: { method }, performance: { now: () => 100 },
      setTimeout: (_callback: unknown, ms: number) => { timers.push(ms); return timers.length; },
      clearTimeout() {}, responseTimedOut() { assert.fail('only timer scheduling is exercised'); },
      deadline: undefined as number | undefined };
    new Script(ts.transpileModule(`let timer, responseDeadline = 0;
      const ${declarations.get('responseTimeoutMs')!.getText(parsed)};
      const ${declarations.get('awaitFrame')!.getText(parsed)};
      awaitFrame(); globalThis.deadline = responseDeadline;`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText).runInNewContext(context);
    const budget = method === 'run.apply' ? 300_000 : 30_000;
    assert.deepEqual(timers, [budget]); assert.equal(context.deadline, 100 + budget);
  }
});
