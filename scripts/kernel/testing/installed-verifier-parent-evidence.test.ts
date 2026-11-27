// Actual data predicates/control flow only. No successful Run, StateOwner,
// native receipt, live /proc observation or Linux qualification is fabricated.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';

async function parsed(name: string) {
  return ts.createSourceFile(name, await readFile(new URL(name, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
}
function nodes<T extends ts.Node>(root: ts.Node, predicate: (node: ts.Node) => node is T): T[] {
  const found: T[] = []; const visit = (node: ts.Node) => { if (predicate(node)) found.push(node); ts.forEachChild(node, visit); };
  visit(root); return found;
}
const compile = (text: string) => ts.transpile(text, { target: ts.ScriptTarget.ES2022 });
const same = (a: unknown, b: unknown) => assert.equal(canonicalSha256(a), canonicalSha256(b));

test('actual Delivery journal selection distinguishes known child Stop from the immutable UNKNOWN, never replay', async () => {
  const file = await parsed('./installed-delivery-result.ts');
  const entry = nodes(file, (node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === 'assertInstalledDeliveryVerifier' && !!node.body)[0]!;
  const selection = nodes(entry, (node): node is ts.VariableStatement => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(value => value.name.getText(file) === 'unknownParent'));
  const assertion = nodes(entry, (node): node is ts.CallExpression => ts.isCallExpression(node) && node.expression.getText(file) === 'same' &&
    node.arguments[0]?.getText(file).startsWith('operation.map(') === true);
  assert.equal(assertion.length, 1);
  const select = new Function('outcome', 'operation', 'same', compile(selection.map(node => node.getText(file)).join('\n') + assertion[0]!.getText(file)));
  const rows = (phase: string) => ['prepared', 'dispatch_claimed', phase].map(phase => ({ phase }));
  select('passed', rows('completed'), same); select('stopped', rows('failed'), same); select('stopped', rows('unknown'), same);
  for (const [outcome, operation] of [['passed', rows('unknown')], ['stopped', rows('completed')],
    ['stopped', [...rows('unknown'), { phase: 'failed' }]], ['stopped', [{ phase: 'unknown' }]]] as const)
    assert.throws(() => select(outcome, operation, same));
});

test('actual parent-domain association refuses a substituted claim, evidence, charge or freshness cut', async () => {
  const file = await parsed('./installed-verifier-parent-evidence.ts');
  const assertion = nodes(file, (node): node is ts.CallExpression => ts.isCallExpression(node) && node.expression.getText(file) === 'check' &&
    node.arguments[0]?.getText(file).startsWith('evidence.runId') === true);
  assert.equal(assertion.length, 1);
  const check = new Function('evidence', 'closure', 'claim', 'terminal', 'prepared', 'run', 'detail', 'parseCanonicalTime',
    compile(`return !!(${assertion[0]!.arguments[0]!.getText(file)});`));
  const at = (n: number) => new Date(Date.UTC(2026, 9, 25) + n).toISOString();
  const data = { evidence: { runId: 'inert-run', opId: 'inert-op', attempt: 0, dispatchId: 'inert-dispatch', unknownJournalSeq: 3, observedAt: at(10) },
    closure: { claimJournalSeq: 2, claimingSupervisorInstanceId: 'inert-owner', claimingStateOwnerEpoch: 1,
      requestRef: 'a', targetRef: 'b', grantRef: 'c', sandboxLaunchSpecRef: 'd', leaseEpoch: 1 },
    claim: { opId: 'inert-op', attempt: 0, dispatchId: 'inert-dispatch', seq: 2, supervisorInstanceId: 'inert-owner',
      stateOwnerEpoch: 1, sandboxLaunchSpecRef: 'd', leaseEpoch: 1 }, terminal: { seq: 3, timestamp: at(5) },
    prepared: { requestRef: 'a', target: 'b', grantRef: 'c' }, run: { id: 'inert-run', updatedAt: at(11) }, detail: { createdAt: at(11) } };
  const invoke = (value: typeof data) => check(...Object.values(value), Date.parse);
  assert.equal(invoke(data), true);
  for (const [record, field] of [['evidence', 'runId'], ['evidence', 'opId'], ['evidence', 'attempt'], ['evidence', 'dispatchId'],
    ['evidence', 'unknownJournalSeq'], ['closure', 'claimJournalSeq'], ['closure', 'claimingSupervisorInstanceId'],
    ['closure', 'claimingStateOwnerEpoch'], ['closure', 'requestRef'], ['closure', 'targetRef'], ['closure', 'grantRef'],
    ['closure', 'sandboxLaunchSpecRef'], ['closure', 'leaseEpoch']] as const) {
    const changed = structuredClone(data); (changed[record] as Record<string, unknown>)[field] = 'different'; assert.equal(invoke(changed), false, `${record}.${field}`);
  }
  for (const [observedAt, detailAt, updatedAt] of [[at(4), at(11), at(11)], [at(10), at(9), at(11)],
    [at(10), at(12), at(11)], [at(10), at(11), at(5011)]]) {
    const changed = structuredClone(data); changed.evidence.observedAt = observedAt!; changed.detail.createdAt = detailAt!; changed.run.updatedAt = updatedAt!;
    assert.equal(invoke(changed), false);
  }
});

test('actual atomic Stop Checkpoint and SQL cut predicates retain source, revision, cancellation and unchanged tree associations', async () => {
  const file = await parsed('./installed-verifier-parent-evidence.ts');
  const checks = nodes(file, (node): node is ts.CallExpression => ts.isCallExpression(node) && node.expression.getText(file) === 'check');
  const cp = checks.find(node => node.arguments[0]?.getText(file).startsWith('checkpoint.id'));
  const sql = checks.find(node => node.arguments[0]?.getText(file).startsWith('row.revision')); assert(cp && sql);
  const checkCp = new Function('checkpoint', 'run', 'terminal', 'cut', 'generation', 'physical', compile(`return !!(${cp.arguments[0]!.getText(file)});`));
  const data = { checkpoint: { id: 'inert-cp', runId: 'inert-run', basedOnRunRevision: 6, createdAt: 'time', journalSeq: 3, workspaceStateRef: 'state' },
    run: { id: 'inert-run', latestCheckpointId: 'inert-cp', revision: 7, updatedAt: 'time' }, terminal: { seq: 3 }, cut: { journal: [{}, {}, {}] },
    generation: { sourceWorkspaceStateRef: 'state', updatedAt: 'time', lastVerifiedTreeDigest: 'tree' },
    physical: { retiredAt: 'time', graph: { quarantine: { observedState: { kind: 'complete_tree', treeDigest: 'tree' } } } } };
  const invoke = (value: typeof data) => checkCp(...Object.values(value)); assert.equal(invoke(data), true);
  for (const field of ['id', 'runId', 'basedOnRunRevision', 'createdAt', 'journalSeq', 'workspaceStateRef'] as const) {
    const changed = structuredClone(data); (changed.checkpoint as Record<string, unknown>)[field] = 'substituted'; assert.equal(invoke(changed), false, field);
  }
  const changed = structuredClone(data); changed.physical.graph.quarantine.observedState.treeDigest = 'other-tree'; assert.equal(invoke(changed), false);
  const checkSql = new Function('row', 'run', compile(`return !!(${sql.arguments[0]!.getText(file)});`));
  const run = { revision: 7, leaseEpoch: 1, status: 'cancelled', stopIntentRef: 'stop', deadlineAt: 'deadline' },
    row = { revision: 7, lease_epoch: 1, status: 'cancelled', cancel_requested: 1, stop_intent_ref: 'stop', deadline_at: 'deadline' };
  assert.equal(checkSql(row, run), true);
  for (const key of Object.keys(row)) assert.equal(checkSql({ ...row, [key]: 'different' }, run), false, key);
});

test('the real independent process loop retains all three recorded known-child or parent lifetimes and does not accept errors as death', async () => {
  const file = await parsed('./installed-node-journey.ts');
  const declaration = nodes(file, (node): node is ts.VariableDeclaration => ts.isVariableDeclaration(node) && node.name.getText(file) === 'assertVerifierProcessesAbsent');
  assert.equal(declaration.length, 1);
  const make = (processStart: (pid: number) => Promise<string>) => new Function('assert', 'processStart', compile(`return (${declaration[0]!.initializer!.getText(file)});`))(assert, processStart);
  const processes = ['namespace_init', 'monitor', 'subreaper'].map((role, i) => ({ role, pid: i + 10, startTicks: '123' }));
  for (const retirement of [{ processes }, { kind: 'unknown_parent_domain', childIdentityRecorded: false, processes }]) {
    const seen: number[] = [];
    await make(async pid => { seen.push(pid); return '456'; })(retirement); assert.deepEqual(seen, [10, 11, 12]);
    await assert.rejects(make(async () => '123')(retirement));
    await make(async () => { throw Object.assign(new Error('gone'), { code: 'ENOENT' }); })(retirement);
    for (const code of ['EACCES', 'ESRCH', undefined])
      await assert.rejects(make(async () => { throw Object.assign(new Error('not absence'), { code }); })(retirement));
  }
  await assert.rejects(make(async () => '456')({ processes: processes.slice(1) }));
  const start = nodes(file, (node): node is ts.VariableDeclaration => ts.isVariableDeclaration(node) && node.name.getText(file) === 'processStart');
  assert.equal(start.length, 1);
  const stat = (state: string) => `10 (inert) ${[state, ...Array(18).fill('0'), '123'].join(' ')}`;
  const parse = (text: string) => new Function('assert', 'readFile', compile(`return (${start[0]!.initializer!.getText(file)});`))(assert, async () => text);
  assert.equal(await parse(stat('S'))(10), '123');
  for (const state of ['Z', 'X', 'x']) await assert.rejects(parse(stat(state))(10));
});

test('initial cancellation and reconnect/restart carry the actual recovered binding to the same strict SQL reader', async () => {
  const file = await parsed('./installed-delivery-journey.ts');
  const calls = nodes(file, (node): node is ts.CallExpression => ts.isCallExpression(node) && node.expression.getText(file) === 'assertInstalledDeliveryVerifier' &&
    node.arguments[0]?.getText(file).includes("outcome: 'stopped'") === true);
  assert.equal(calls.length, 2);
  for (const call of calls) {
    let captured: any;
    const inspect = new Function('assertInstalledDeliveryVerifier', 'cancelled', 'cancelledSource', 'context', 'cancellation', 'cancellationResponse',
      compile(`return (${call.getText(file)});`));
    const reader = () => { throw new Error('data-only callback must not be invoked'); };
    const context = { readRetainedArtifact: reader, readOwnerHistory: reader, readParentRetirement: reader };
    inspect((value: unknown) => { captured = value; }, { inert: true }, { cut: { inertSource: true } }, context, {}, {});
    assert.equal(captured.readParentRetirement, reader); assert.equal(captured.readRetainedArtifact, reader); assert.equal(captured.readOwnerHistory, reader);
  }
  const retirements = nodes(file, (node): node is ts.VariableDeclaration => ts.isVariableDeclaration(node) && node.name.getText(file) === 'retirements');
  assert.equal(retirements.length, 1);
  const callArgs: unknown[][] = [], binding = { inertParent: true };
  const retire = new Function('context', 'observedLaunches', compile(`return (${retirements[0]!.initializer!.getText(file)});`))(
    { assertRunWorkersRetired(...values: unknown[]) { callArgs.push(values); return 1; } }, new Map([['inert-run', new Set(['inert-launch'])]]));
  await retire('inert-run', undefined, binding);
  assert.deepEqual(callArgs, [['inert-run', ['inert-launch'], undefined, binding]]);
});

test('closed campaign summary never calls an unrecorded UNKNOWN child a qualified independent child cut', async () => {
  const file = await parsed('./installed-delivery-journey.ts');
  const summaries = nodes(file, (node): node is ts.PropertyAssignment => ts.isPropertyAssignment(node) &&
    ['exactVerifierProcessLifetimesIndependentlyAbsent', 'cancellationRetirement'].includes(node.name.getText(file)));
  assert.equal(summaries.length, 2);
  const summary = new Function('parentRetirement', compile(`return ({${summaries.map(node => node.getText(file)).join(',')}});`));
  assert.deepEqual(summary(undefined), { exactVerifierProcessLifetimesIndependentlyAbsent: true,
    cancellationRetirement: { kind: 'known_child_stop', childProcessLifetimesIndependentlyAbsent: true } });
  assert.deepEqual(summary({ inert: true }), { exactVerifierProcessLifetimesIndependentlyAbsent: false,
    cancellationRetirement: { kind: 'unknown_parent_domain', childIdentityRecorded: false,
      parentProcessLifetimesIndependentlyAbsent: true, originalControllerRetirementVerified: true } });
});
