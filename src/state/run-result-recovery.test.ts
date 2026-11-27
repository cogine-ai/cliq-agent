// Pure canonical timing contract only; no terminal, native or publication authority.
// The real finalization predicate over inert retained data only. This does not
// run the preceding SQL/CAS graph or create a Run, StateOwner or native proof.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { identityHash } from '../kernel/identity.js';
import { deliveryPublicationCheckpointId, deliveryPublicationTerminalCheckpointId } from './delivery-publication-progress.js';
import { assertRunResultPreparationTime } from './run-result-recovery.js';

test('atomic delivery truthfully prepares immutable result bytes after observation and before its SQL Checkpoints', () => {
  assert.doesNotThrow(() => assertRunResultPreparationTime('delivery', '2026-01-01T00:00:01.000Z',
    '2026-01-01T00:00:02.000Z', '2026-01-01T00:00:02.000Z', '2026-01-01T00:00:00.000Z'));
  assert.throws(() => assertRunResultPreparationTime('agent', '2026-01-01T00:00:01.000Z',
    '2026-01-01T00:00:02.000Z', '2026-01-01T00:00:02.000Z'));
});

test('terminal timing refuses missing observations, future preparation and a separate publication transaction', () => {
  const observation = '2026-01-01T00:00:01.000Z', preparation = '2026-01-01T00:00:02.000Z', commit = '2026-01-01T00:00:03.000Z';
  const invalid: Parameters<typeof assertRunResultPreparationTime>[] = [
    ['delivery', preparation, commit, commit],
    ['delivery', observation, commit, commit, preparation],
    ['delivery', commit, preparation, preparation, observation],
    ['delivery', preparation, preparation, commit, observation],
    ['delivery', preparation, commit, commit, 'not-canonical'],
  ];
  for (const values of invalid) assert.throws(() => assertRunResultPreparationTime(...values));
  assert.throws(() => assertRunResultPreparationTime('unknown' as never, preparation, preparation, commit));
  assert.doesNotThrow(() => assertRunResultPreparationTime('delivery', observation, observation, observation, observation));
  assert.doesNotThrow(() => assertRunResultPreparationTime('agent', preparation, observation, commit));
});

async function finalizationGuard() {
  const source = ts.createSourceFile('run-result-recovery.ts', await readFile(
    new URL('./run-result-recovery.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declaration = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'readFinalizationData');
  assert(declaration?.body, 'the original retained finalization reader must exist');
  const guards: ts.IfStatement[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && ts.isThrowStatement(node.thenStatement) &&
        ts.isNewExpression(node.thenStatement.expression) &&
        node.thenStatement.expression.expression.getText(source) === 'TypeError' &&
        node.thenStatement.expression.arguments?.[0]?.getText(source) ===
          "'delivery terminal projection differs from its carried verified merge'") guards.push(node);
    ts.forEachChild(node, visit);
  };
  visit(declaration.body);
  assert.equal(guards.length, 1, 'execute the original complete delivery finalization rejection predicate');
  const physical: ts.VariableDeclaration[] = [];
  const findPhysical = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'physical') physical.push(node);
    ts.forEachChild(node, findPhysical);
  };
  findPhysical(declaration.body);
  assert.equal(physical.length, 1);
  assert(physical[0]!.pos < guards[0]!.pos, 'complete physical projection validation must precede the derived Checkpoint role');
  assert.equal(physical[0]!.initializer?.getText(source),
    'delivery ? await delivery.terminalProjection(projectionRef) : await readDeliveryTerminalProjection(driver, artifacts, cut, projectionRef)');
  return new Function('physical', 'basis', 'verified', 'cut', 'projectionRef', 'identityHash', guards[0]!.getText(source));
}

function retainedData() {
  const runId = 'retained-data-delivery', planRef = identityHash('retained complete plan'),
    sourceRef = identityHash('retained desired source'), projectionRef = identityHash('retained physical projection');
  return { projectionRef, cut: { run: { id: runId } }, basis: { candidate: { resultSourceRef: sourceRef } },
    verified: { deliveryPlanRef: planRef, deliveryPlan: { forwardOperations: [{}] },
      checkpoint: { createdAt: '2026-10-25T00:00:00.000Z' } },
    physical: { evidenceRef: projectionRef, evidence: { selectedBranch: 'forward_finalize', observedSourceRef: sourceRef,
      deliveryPlanRef: planRef }, checkpoint: { id: deliveryPublicationTerminalCheckpointId(runId, planRef),
      createdAt: '2026-10-25T00:00:01.000Z' } } };
}

test('retained finalization accepts the terminal Checkpoint of a nonempty received publication', async () => {
  const guard = await finalizationGuard(), data = retainedData();
  assert.doesNotThrow(() => guard(data.physical, data.basis, data.verified, data.cut, data.projectionRef, identityHash));
});

test('retained finalization keeps no-op seal and nonempty terminal Checkpoint roles distinct', async () => {
  const guard = await finalizationGuard();
  for (const operationCount of [0, 1, 2]) {
    const data = retainedData(); data.verified.deliveryPlan.forwardOperations = Array.from({ length: operationCount }, () => ({}));
    const correct = operationCount ? deliveryPublicationTerminalCheckpointId : deliveryPublicationCheckpointId;
    const wrong = operationCount ? deliveryPublicationCheckpointId : deliveryPublicationTerminalCheckpointId;
    data.physical.checkpoint.id = correct(data.cut.run.id, data.verified.deliveryPlanRef);
    assert.doesNotThrow(() => guard(data.physical, data.basis, data.verified, data.cut, data.projectionRef, identityHash));
    data.physical.checkpoint.id = wrong(data.cut.run.id, data.verified.deliveryPlanRef);
    assert.throws(() => guard(data.physical, data.basis, data.verified, data.cut, data.projectionRef, identityHash),
      { name: 'TypeError', message: 'delivery terminal projection differs from its carried verified merge' });
  }
});

test('retained finalization rejects foreign run or Plan Checkpoint names in both roles', async () => {
  const guard = await finalizationGuard();
  for (const operationCount of [0, 1]) for (const foreign of ['run', 'plan', 'both']) {
    const data = retainedData(); data.verified.deliveryPlan.forwardOperations.length = operationCount;
    const derive = operationCount ? deliveryPublicationTerminalCheckpointId : deliveryPublicationCheckpointId;
    data.physical.checkpoint.id = derive(foreign === 'plan' ? data.cut.run.id : 'foreign-run',
      foreign === 'run' ? data.verified.deliveryPlanRef : identityHash('foreign complete plan'));
    assert.throws(() => guard(data.physical, data.basis, data.verified, data.cut, data.projectionRef, identityHash),
      { name: 'TypeError', message: 'delivery terminal projection differs from its carried verified merge' });
  }
});

test('retained finalization preserves the projection, branch, desired source, Plan and time refusals', async () => {
  const guard = await finalizationGuard();
  const mutations: ReadonlyArray<readonly [string, (data: ReturnType<typeof retainedData>) => void]> = [
    ['projection', data => { data.physical.evidenceRef = identityHash('foreign projection'); }],
    ['branch', data => { data.physical.evidence.selectedBranch = 'abort_finalize'; }],
    ['source', data => { data.physical.evidence.observedSourceRef = identityHash('foreign source'); }],
    ['plan', data => { data.physical.evidence.deliveryPlanRef = identityHash('foreign plan'); }],
    ['time', data => { data.physical.checkpoint.createdAt = '2026-10-24T23:59:59.999Z'; }]
  ];
  for (const operationCount of [0, 1]) {
    const original = retainedData(); original.verified.deliveryPlan.forwardOperations.length = operationCount;
    original.physical.checkpoint.id = (operationCount ? deliveryPublicationTerminalCheckpointId : deliveryPublicationCheckpointId)(
      original.cut.run.id, original.verified.deliveryPlanRef);
    original.physical.checkpoint.createdAt = original.verified.checkpoint.createdAt;
    assert.doesNotThrow(() => guard(original.physical, original.basis, original.verified, original.cut, original.projectionRef, identityHash),
      'equal canonical timestamps remain allowed');
    for (const [name, mutate] of mutations) {
      const data = structuredClone(original); mutate(data);
      assert.throws(() => guard(data.physical, data.basis, data.verified, data.cut, data.projectionRef, identityHash),
        { name: 'TypeError', message: 'delivery terminal projection differs from its carried verified merge' }, name);
    }
  }
});

test('the preceding physical reader still refuses a nonempty forward projection without its complete received handoff', async () => {
  const source = ts.createSourceFile('delivery-publication-recovery.ts', await readFile(
    new URL('./delivery-publication-recovery.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declaration = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'readDeliveryTerminalProjectionData');
  assert(declaration?.body);
  const guards: ts.IfStatement[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && ts.isThrowStatement(node.thenStatement) &&
        ts.isNewExpression(node.thenStatement.expression) && node.thenStatement.expression.arguments?.[0]?.getText(source) ===
          "'forward publication lacks its complete unstopped ordered native result closure'") guards.push(node);
    ts.forEachChild(node, visit);
  };
  visit(declaration.body); assert.equal(guards.length, 1);
  const guard = new Function('noOp', 'handedOff', 'cut', 'checkpoint', 'forwardClaims', 'plan', 'prefix', 'evidence', guards[0]!.getText(source));
  const cut = { run: { deadlineAt: '2026-10-25T00:00:02.000Z' } }, checkpoint = { createdAt: '2026-10-25T00:00:01.000Z' },
    plan = { forwardOperations: [{}], desiredSourceRef: identityHash('desired source') },
    prefix = { forward: [{ result: { item: { outcome: 'completed' } } }], abort: [] }, evidence = { observedSourceRef: plan.desiredSourceRef };
  assert.throws(() => guard(false, false, cut, checkpoint, [{}], plan, prefix, evidence),
    { name: 'TypeError', message: 'forward publication lacks its complete unstopped ordered native result closure' });
  assert.doesNotThrow(() => guard(false, true, cut, checkpoint, [{}], plan, prefix, evidence));
  assert.doesNotThrow(() => guard(true, false, cut, checkpoint, [], { ...plan, forwardOperations: [] }, { forward: [], abort: [] }, evidence));
});
