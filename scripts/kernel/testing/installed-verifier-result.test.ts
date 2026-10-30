// Fixed diagnostic data and source wiring only, never a successful retirement
// graph, native proof, StateOwner, Run authority or physical qualification.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';
import vm from 'node:vm';
import { InstalledVerifierOutcomeError } from './installed-verifier-result.js';

test('real provider candidate eligibility allows only its original repair budget and leaves every fixed fixture strict', () => {
  // These are only the actual pure cardinality predicates. Native receipts,
  // retirement and repair-plan reconstruction remain required afterwards.
  const source = readFileSync(new URL('./installed-verifier-result.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('result.ts', source, ts.ScriptTarget.Latest, true);
  let candidates: ts.IfStatement | undefined, repairs: ts.CallExpression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.expression.getText(parsed) === "caseKind === 'required_provider'") candidates = node;
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'check' && node.arguments[0]?.getText(parsed).startsWith('repairs.length ===')) repairs = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(candidates && repairs);
  const predicates = ts.transpileModule(candidates.getText(parsed) + '\n' + repairs.getText(parsed),
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const accepts = (caseKind: string, candidateCount: number, repairCount: number, budget: number, claimedRepairs = repairCount) => {
    const context = { caseKind, candidates: Array(candidateCount), repairs: Array(repairCount), spec: { budgets: { repairAttempts: budget } },
      run: { repairCount: claimedRepairs, budgetConsumed: { repairAttempts: claimedRepairs } }, check: assert.ok };
    try { vm.runInNewContext(predicates, context); return true; } catch { return false; }
  };
  for (const [count, repair] of [[1, 0], [2, 1], [3, 2]]) assert.equal(accepts('required_provider', count!, repair!, 2), true);
  for (const [count, repair, budget, claimed] of [[0, 0, 2, 0], [4, 3, 2, 3], [2, 0, 2, 1], [3, 1, 2, 2], [1, 0, 2, 2]])
    assert.equal(accepts('required_provider', count!, repair!, budget!, claimed!), false);
  for (const caseKind of ['required_pass', 'advisory_failure', 'required_timeout']) {
    assert.equal(accepts(caseKind, 1, 0, 2), true); assert.equal(accepts(caseKind, 2, 1, 2), false);
  }
  assert.equal(accepts('required_repair', 2, 1, 2), true); assert.equal(accepts('required_repair', 3, 2, 2), false);
  const reconstructed = source.indexOf('const expected = planVerifierRepair(progress,');
  const balanced = source.indexOf('const consumed = { ...ZERO, repairAttempts: repairs.length }');
  assert(reconstructed >= 0 && balanced > reconstructed);
  assert(source.slice(reconstructed, balanced).includes('same(repair, expected.item)'));
  assert(source.slice(reconstructed, balanced).includes('same(await object(plan.ref), parseJsonStrict(Buffer.from(plan.bytes)'));
  assert(source.slice(reconstructed, balanced).includes("const messages = projection.messages.filter((message: any) => message.sourceKind === 'verifier_repair')"));
  assert(source.includes('const physical = await assertInstalledVerifierRetirement('));
});
const stages = ['public_cut', 'frozen_inputs', 'source_and_candidate', 'candidate_producer', 'candidate_source',
  'verifier_request', 'verifier_policy_and_attempt', 'verifier_settlement', 'verifier_receipt', 'verifier_retirement',
  'verifier_retirement_request', 'verifier_retirement_source', 'verifier_retirement_projection', 'verifier_retirement_launch',
  'verifier_retirement_child', 'verifier_retirement_parent', 'verifier_retirement_inspector', 'verifier_retirement_processes', 'verifier_retirement_output',
  'verifier_retirement_state', 'verifier_retirement_context', 'verifier_retirement_item_seq',
  'reverse_history_and_repair', 'terminal_result', 'session_publication'] as const;
const inspectorStages = (['assembly', 'bundle', 'history', 'history_open', 'history_snapshot', 'history_schema', 'history_rows',
  'history_records', 'history_fence', 'history_commit', 'owners', 'identity', 'binding', 'claim', 'process', 'lock', 'root',
  'acquisition', 'digests', 'fields'] as const).map(stage => `verifier_retirement_inspector_${stage}` as const);

test('the real installed verifier error retains the fixed old stages and three retirement assertion stages without a cause', () => {
  for (const stage of [...stages, ...inspectorStages]) {
    const error = new InstalledVerifierOutcomeError(stage);
    assert.equal(error.diagnosticStage, stage);
    assert.equal(error.code, 'INSTALLED_VERIFIER_OUTCOME_REFUSED');
    assert.equal(error.name, 'InstalledVerifierOutcomeError');
    assert.equal(error.message, `Installed verifier outcome refused at ${stage}`);
    assert.equal(Object.hasOwn(error, 'cause'), false, 'no original decoder error is retained as a cause');
  }
});

test('inspector diagnostics label the original deep checks and thread the real readonly SQL phases', () => {
  const source = readFileSync(new URL('./installed-verifier-evidence.ts', import.meta.url), 'utf8');
  for (const stage of inspectorStages) assert(source.includes(`'${stage}'`), stage);
  const ordered = [
    ["phase('verifier_retirement_inspector_assembly')", 'decodeRetainedRunAssembly(await object(requestContext.assemblyRef))'],
    ["phase('verifier_retirement_inspector_bundle')", 'const bundle = await object(assembly.runtime.runtimeBundleRef)'],
    ["phase('verifier_retirement_inspector_history')", 'const values = await input.readOwnerHistory(stage =>'],
    ["phase('verifier_retirement_inspector_owners')", 'const owners = values.map(value => decodeStateOwnerRecord(value))'],
    ["phase('verifier_retirement_inspector_identity')", 'const inspector = await object(observation.inspectorIdentityRef)'],
    ["phase('verifier_retirement_inspector_binding')", 'check(inspector.identityDigest === observation.inspectorIdentityDigest'],
    ["phase('verifier_retirement_inspector_claim')", 'if (observation === death) check(owner.ownerEpoch === claim.stateOwnerEpoch'],
    ["phase('verifier_retirement_inspector_process')", 'const process = decodePlatformProcessIdentity(await object(owner.processIdentityRef))'],
    ["phase('verifier_retirement_inspector_lock')", 'const lock = decodeStateLockIdentity(await object(owner.stateLockIdentityRef))'],
    ["phase('verifier_retirement_inspector_root')", 'const root = decodeStateRootIdentity(await object(lock.stateRootIdentityRef))'],
    ["phase('verifier_retirement_inspector_acquisition')", 'const acquired = decodeStateOwnerAcquisitionEvidence(await object(owner.acquisitionEvidenceRef))'],
    ["phase('verifier_retirement_inspector_digests')", 'check(process.identityDigest === owner.processIdentityDigest'],
    ["phase('verifier_retirement_inspector_fields')", "for (const field of ['ownerEpoch', 'supervisorInstanceId'"]
  ];
  const original = source.slice(source.indexOf('export async function assertInstalledVerifierRetirement('));
  for (const [note, operation] of ordered) assert(original.indexOf(note!) >= 0 && original.indexOf(note!) < original.indexOf(operation!), note);
  const consumer = readFileSync(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('installed-node-journey.ts', consumer, ts.ScriptTarget.Latest, true);
  const readers: ts.PropertyAssignment[] = [];
  const collect = (node: ts.Node): void => {
    if (ts.isPropertyAssignment(node) && node.name.getText(parsed) === 'readOwnerHistory') readers.push(node);
    ts.forEachChild(node, collect);
  };
  collect(parsed);
  assert.deepEqual(readers.map(reader => {
    assert.equal(reader.initializer.getText(parsed),
      'async (observe?: (stage: InstalledOwnerHistoryReadStage) => void) => inspectInstalledOwnerHistory(recipe.stateRoot, observe).owners');
    assert(ts.isObjectLiteralExpression(reader.parent));
    const owner = reader.parent.parent;
    if (ts.isCallExpression(owner)) return owner.expression.getText(parsed);
    assert(ts.isVariableDeclaration(owner)); return owner.name.getText(parsed);
  }), ['assertInstalledVerifierOutcome', 'assertInstalledVerifierOutcome', 'assertInstalledVerifierOutcome',
    'runInstalledDeliveryCases', 'readInstalledPublicationProbeSample', 'recoveryInput']);
  const dailyProof = readers[0]!;
  let scope: ts.Node | undefined = dailyProof.parent;
  while (scope && !(ts.isPropertyAssignment(scope) && scope.name.getText(parsed) === 'verifySource')) scope = scope.parent;
  assert(scope, 'the additive daily verifier must use the same complete original readonly owner history');
  assert(source.includes("typeof stage === 'string' && Object.hasOwn(ownerHistoryPhases, stage)"));
});

test('the real diagnostic class never treats arbitrary extra arguments as messages or cause options', () => {
  let touched = 0;
  const bad = () => { touched++; throw new Error('private-value-must-not-escape'); };
  for (const extra of ['private-workspace-message', { cause: new Error('private-cause') },
    Object.defineProperty({}, 'cause', { get: bad }),
    new Proxy({}, { get: bad, getPrototypeOf: bad, ownKeys: bad, getOwnPropertyDescriptor: bad })]) {
    const error = Reflect.construct(InstalledVerifierOutcomeError, ['verifier_retirement_context', extra]) as InstalledVerifierOutcomeError;
    assert.equal(error.message, 'Installed verifier outcome refused at verifier_retirement_context');
    assert.equal(error.diagnosticStage, 'verifier_retirement_context');
    assert.equal(Object.hasOwn(error, 'cause'), false);
  }
  assert.equal(touched, 0);
});

test('retirement stage labels preserve the exact original proof, state, context and item-sequence checks in order', () => {
  const source = readFileSync(new URL('./installed-verifier-result.ts', import.meta.url), 'utf8');
  const proof = source.indexOf("stage = 'verifier_retirement';");
  const physical = source.indexOf('const physical = await assertInstalledVerifierRetirement(', proof);
  const checkpoint = source.indexOf('const cp = physical.checkpoint;', physical);
  const stateStage = source.indexOf("stage = 'verifier_retirement_state';", checkpoint);
  const state = source.indexOf('await state(cp, source.entriesRef);', stateStage);
  const contextStage = source.indexOf("stage = 'verifier_retirement_context';", state);
  const context = source.indexOf('await context(cp);', contextStage);
  const itemStage = source.indexOf("stage = 'verifier_retirement_item_seq';", context);
  const item = source.indexOf('check(cp.runItemSeq === resultRow.itemSeq);', itemStage);
  const retained = source.indexOf('retirementIdentities.push(physical.identity);', item);
  assert(proof >= 0 && physical > proof && checkpoint > physical && stateStage > checkpoint && state > stateStage &&
    contextStage > state && context > contextStage && itemStage > context && item > itemStage && retained > item,
  'each fixed label must precede its unchanged original assertion, without skipping the original retirement graph');
  assert(source.includes('throw new InstalledVerifierOutcomeError(stage);'));
});

test('the shared retirement observer updates only the existing fixed outer error stage', () => {
  const source = readFileSync(new URL('./installed-verifier-result.ts', import.meta.url), 'utf8');
  const start = source.indexOf('const physical = await assertInstalledVerifierRetirement(');
  const end = source.indexOf('const cp = physical.checkpoint;', start);
  assert(start >= 0 && end > start, 'the complete shared retirement read must remain awaited');
  assert(source.slice(start, end).includes('readRetainedArtifact: bytes, readOwnerHistory: input.readOwnerHistory }, value => { stage = value; });'),
    'only the fixed observer phase may update the existing outer diagnostic stage');
});
