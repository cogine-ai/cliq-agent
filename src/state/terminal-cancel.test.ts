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

test('terminal cancellation observes each original serial consumer without adding authority or work', async () => {
  const { INSTALLED_PUBLICATION_WORK_V2, INSTALLED_RUN_FAILURE_CHANNEL, observeInstalledPublicationWork } =
    await import('./installed-run-diagnostics.js');
  const { channel } = await import('node:diagnostics_channel');
  const names = ['terminal_cancel_authority', 'terminal_cancel_material', 'terminal_cancel_control', 'terminal_cancel_stop'];
  for (const name of names) assert((INSTALLED_PUBLICATION_WORK_V2 as readonly string[]).includes(name), name);
  const text = readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('store.ts', text, ts.ScriptTarget.Latest, true);
  let method: ts.MethodDeclaration | undefined;
  const visit = (node: ts.Node) => { if (ts.isMethodDeclaration(node) && node.name.getText(file) === 'cancelTerminalInstalledRun') method = node;
    ts.forEachChild(node, visit); }; visit(file); assert(method?.body);
  const calls: ts.CallExpression[] = [];
  const gather = (node: ts.Node) => { if (ts.isCallExpression(node) && node.expression.getText(file) === 'observeInstalledPublicationWork') calls.push(node);
    ts.forEachChild(node, gather); }; gather(method.body);
  assert.deepEqual(calls.map(call => (call.arguments[1] as ts.StringLiteral).text), names);
  const consumers = ['readRunAuthority(', 'loadInstalledRunMaterial(', 'authority.controlAuthority.assertAuthority(signal)', '.cancelRun(command)'];
  for (const [index, call] of calls.entries()) {
    assert.equal(call.arguments[0]?.getText(file), 'runId');
    const callback = call.arguments[2]; assert(callback && ts.isArrowFunction(callback));
    assert(callback.body.getText(file).includes(consumers[index]!));
    assert(ts.isAwaitExpression(call.parent) || ts.isReturnStatement(call.parent), 'one original awaited/returned promise, no fire and forget');
  }
  assert.doesNotMatch(method.body.getText(file), /Promise\.(all|race)|setTimeout|performance\.now|Date\.now|catch\s*\(/u);
  const diagnostic = channel(INSTALLED_RUN_FAILURE_CHANNEL), records: any[] = [];
  const receive = (value: unknown) => records.push(value); diagnostic.subscribe(receive);
  try {
    const original = new Error('private original refusal');
    const observe = observeInstalledPublicationWork as (runId: string, name: string, read: () => Promise<unknown>) => Promise<unknown>;
    assert.equal(await observe('a'.repeat(43), names[0]!, async () => 17), 17);
    await assert.rejects(observe('a'.repeat(43), names[1]!, async () => { throw original; }), error => error === original);
    assert.deepEqual(records.map(row => [row.work, row.event]), [[names[0], 'begin'], [names[0], 'fulfilled'], [names[1], 'begin'], [names[1], 'rejected']]);
    assert(records.every(row => Object.isFrozen(row) && Number.isSafeInteger(row.elapsedMs) && row.elapsedMs >= 0));
    assert(!JSON.stringify(records).includes(original.message));
  } finally { diagnostic.unsubscribe(receive); }
});

test('cancel diagnostics preserve authenticated routing and the retained-agent stop before native revocation', () => {
  const text = readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('store.ts', text, ts.ScriptTarget.Latest, true);
  let method: ts.MethodDeclaration | undefined;
  const visit = (node: ts.Node) => { if (ts.isMethodDeclaration(node) && node.name.getText(file) === 'cancelInstalledRun') method = node;
    ts.forEachChild(node, visit); }; visit(file); assert(method?.body);
  const calls: ts.CallExpression[] = [];
  const gather = (node: ts.Node) => { if (ts.isCallExpression(node) && node.expression.getText(file) === 'observeInstalledPublicationWork') calls.push(node);
    ts.forEachChild(node, gather); }; gather(method.body);
  assert.deepEqual(calls.map(call => (call.arguments[1] as ts.StringLiteral).text), ['run_cancel_channel', 'run_cancel_load', 'run_cancel_stop']);
  const consumers = ['validateControlChannelClosure(this.artifacts, this.owner, identity)', 'this.retainInstalledAgent(runId)', 'retainedAgent.cancelRun('];
  for (const [index, call] of calls.entries()) {
    assert.equal(call.arguments[0]?.getText(file), index === 0 ? 'value.runId as string' : 'runId');
    const callback = call.arguments[2]; assert(callback && ts.isArrowFunction(callback));
    assert(callback.body.getText(file).includes(consumers[index]!)); assert(ts.isAwaitExpression(call.parent));
  }
  const body = method.body.getText(file), positions = ['immutableSnapshot(request)', 'requestDigest !== canonicalSha256(core)',
    "'run_cancel_channel'", 'this.installedAgents.get(runId)', 'readRun(this.driver, runId)', 'cancelTerminalInstalledRun(',
    "'run_cancel_load'", "'run_cancel_stop'", 'this.requestInstalledRunStop(runId)', 'this.scheduleInstalledRun(runId)'].map(value => body.indexOf(value));
  assert(positions.every((value, index) => value >= 0 && (index === 0 || value > positions[index - 1]!)));
  assert.doesNotMatch(body, /Promise\.(all|race)|setTimeout|performance\.now|Date\.now|catch\s*\(/u);
});
