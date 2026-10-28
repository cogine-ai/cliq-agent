import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

// Read-only wiring/branch regression. This never constructs a Store,
// StateOwner, Run, installed selection or execution/retirement evidence.
test('a retired terminal Run uses the authenticated cancellation reader before execution reconstruction', () => {
  const text = readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('store.ts', text, ts.ScriptTarget.Latest, true);
  const methods = new Map<string, ts.MethodDeclaration>();
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node)) methods.set(node.name.getText(file), node);
    ts.forEachChild(node, visit);
  }; visit(file);
  const cancel = methods.get('cancelInstalledRun')?.body; assert(cancel);
  const branch = cancel.statements.find((node): node is ts.IfStatement => ts.isIfStatement(node) &&
    node.thenStatement.getText(file).includes('cancelTerminalInstalledRun'));
  assert(branch, 'terminal refusal must not reconstruct a productive continuation');
  const choose = new Function('agent', 'terminal', `return (${branch.expression.getText(file)});`) as
    (agent: unknown, terminal: boolean) => boolean;
  assert.equal(choose(undefined, true), true);
  assert.equal(choose(undefined, false), false);
  assert.equal(choose(Object.freeze({ diagnosticOnly: true }), true), false,
    'an already retained continuation keeps its original owner and cancellation path');
  assert(cancel.getText(file).indexOf(branch.getText(file)) < cancel.getText(file).indexOf('this.retainInstalledAgent('));
  const terminal = methods.get('cancelTerminalInstalledRun')?.body; assert(terminal);
  const body = terminal.getText(file);
  for (const required of ['this.ownInstalledAdmission(', 'withReadSignal(signal)', 'readRunAuthority(',
    'loadInstalledRunMaterial(', 'validateAgentRunAssembly(', 'authority.controlAuthority.assertAuthority(signal)',
    'loadAgentStop(', '.cancelRun(command)']) assert(body.includes(required), required);
  assert.doesNotMatch(body, /loadAgentRun\(|loadRunExecution\(|requestInstalledRunStop\(|scheduleInstalledRun\(/u);
  assert(body.indexOf('readRunAuthority(') < body.indexOf('loadInstalledRunMaterial('),
    'nested four-reader groups remain serial, never two overlapping pools');
  assert(body.indexOf('validateAgentRunAssembly(') < body.indexOf('.cancelRun(command)'));
  const agent = readFileSync(new URL('./reducers/agent.ts', import.meta.url), 'utf8');
  assert.equal(agent.match(/validateRunAssembly\(/gu)?.length, 1,
    'execution and terminal refusal must share the original complete assembly validator');
  assert.equal(agent.match(/validateAgentRunAssembly\(authority, material\)/gu)?.length, 1,
    'productive loading still invokes that same validation');
});
