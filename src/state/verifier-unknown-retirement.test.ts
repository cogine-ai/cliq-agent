import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';
import { hasOnlySettledInstalledModelUnknowns } from './worker-recovery.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, InvocationJournalEntry, RunSpec, SourceManifest, SourceProjectionSpec,
  WorkspaceEntryManifest, WorkspaceStateManifest } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readNativeRetainedWorkerRetirement } from '../sandbox/linux-worker.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readWorkerRecoveryTerminalPlan } from './worker-recovery-terminal.js';
import { readCandidateSource } from './result-source.js';
import { decodeSourceManifest, decodeWorkspaceState } from './decoders.js';
import { decodeVerifierParentDomainDispatchClosure, hasOnlySettledVerifierUnknowns,
  type VerifierParentDomainDispatchClosureV1 } from './verifier-unknown-retirement.js';

// Execute the real reducer's data-only quarantine eligibility condition. This
// is not a StateOwner, broker-quiescence or native-retirement fixture.
async function quarantineRefused(verifierUnknown: boolean, stopped = true): Promise<boolean> {
  const source = await readFile(new URL('./reducers/worker-recovery.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('worker-recovery.ts', source, ts.ScriptTarget.Latest, true);
  let condition: ts.Expression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.thenStatement.getText(file).includes(
      'open worker invocations require their typed settlement or explicit manual-risk wait before quarantine')) condition = node.expression;
    ts.forEachChild(node, visit);
  };
  visit(file); assert.ok(condition, 'actual quarantine refusal condition');
  const expression = ts.transpile(`(${condition.getText(file)})`, { target: ts.ScriptTarget.ES2022 });
  return new Function('hasOnlySettledInstalledModelUnknowns', 'hasOnlySettledVerifierUnknowns',
    'assembly', 'cut', 'privateRollback', 'undispatched', 'publication', 'brokerQuiescence', 'run',
    `return ${expression}`)(() => false, () => verifierUnknown, {}, { journal: [] }, false, false, undefined, true,
      { stopIntentRef: stopped ? 'stop' : undefined });
}

test('stopped verifier UNKNOWN can enter its typed parent-domain retirement, not remain permanently blocked', async () => {
  assert.equal(await quarantineRefused(true), false);
  assert.equal(await quarantineRefused(false), true);
  assert.equal(await quarantineRefused(true, false), true);
  assert.equal(typeof hasOnlySettledInstalledModelUnknowns, 'function');
});

const ref = (digit: string) => digit.repeat(64);
function journal(): InvocationJournalEntry[] {
  const prepared: InvocationJournalEntry = { seq: 1, runId: 'data-run', opId: 'data-verifier', opKind: 'verifier', attempt: 0,
    leaseEpoch: 1, phase: 'prepared', target: ref('a'), requestRef: ref('b'), grantRef: ref('c'), replayClass: 'retry',
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: '2026-10-25T00:00:00.000Z' };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'data-dispatch',
    sandboxLaunchSpecRef: ref('d'), supervisorInstanceId: 'data-supervisor', stateOwnerEpoch: 1,
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
  return [prepared, claim, { ...claim, seq: 3, phase: 'unknown', budgetDelta: { ...prepared.budgetDelta },
    budgetSettlementRef: ref('e'), evidenceRef: ref('f'), evidenceDigest: ref('f') }];
}

test('verifier parent retirement eligibility preserves the one original full settlement and cannot admit another open dispatch', () => {
  const data = journal(), before = structuredClone(data);
  assert.equal(hasOnlySettledVerifierUnknowns(data), true);
  assert.deepEqual(data, before);
  for (const phase of ['prepared', 'dispatch_claimed', 'completed', 'failed'] as const) {
    const changed = structuredClone(data); changed[2]!.phase = phase;
    assert.equal(hasOnlySettledVerifierUnknowns(changed), false, phase);
  }
  for (const field of ['budgetSettlementRef', 'evidenceRef', 'evidenceDigest'] as const) {
    const changed = structuredClone(data); delete changed[2]![field];
    assert.equal(hasOnlySettledVerifierUnknowns(changed), false, field);
  }
  for (const dimension of ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts'] as const) {
    const changed = structuredClone(data); changed[2]!.budgetDelta[dimension]++;
    assert.equal(hasOnlySettledVerifierUnknowns(changed), false, dimension);
  }
  const other = { ...data[0]!, seq: 4, opId: 'another-open-dispatch' };
  assert.equal(hasOnlySettledVerifierUnknowns([...data, other]), false);
  assert.equal(hasOnlySettledVerifierUnknowns([]), false);
  for (const opKind of ['model', 'tool', 'publish'] as const)
    assert.equal(hasOnlySettledVerifierUnknowns(data.map(entry => ({ ...entry, opKind }))), false);
});

function closureData(): VerifierParentDomainDispatchClosureV1 {
  const value: VerifierParentDomainDispatchClosureV1 = { schemaVersion: 1,
    format: 'cliq-invocation-dispatch-closure-evidence-v1', runId: 'data-run', opId: 'data-verifier', attempt: 0,
    dispatchId: 'data-dispatch', unknownJournalSeq: 3, closure: { kind: 'verifier_parent_domain_dead', claimJournalSeq: 2,
      claimingSupervisorInstanceId: 'data-supervisor', claimingStateOwnerEpoch: 1,
      requestRef: ref('a'), targetRef: ref('b'), grantRef: ref('c'), sandboxLaunchSpecRef: ref('d'),
      workerLaunchId: 'data-worker', leaseEpoch: 1, generationRef: ref('e'), parentContainmentRef: ref('f'),
      parentDeathEvidenceRef: ref('1'), parentDeathEvidenceDigest: ref('2'), quarantineEvidenceRef: ref('3'),
      quarantineEvidenceDigest: ref('4'), retirementEvidenceRef: ref('5'), retirementEvidenceDigest: ref('6'),
      controllerLifetime: 'original_subreaper_absent_and_inspector_joined' },
    observedAt: '2026-10-25T00:00:01.000Z', evidenceDigest: '' };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); return value;
}

test('the parent-domain decoder and real CAS preserve only exact closed inert evidence, not native authority', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-verifier-domain-data-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root)), data = closureData();
  const stored = await artifacts.publishCanonical(data, data.format);
  assert.equal(stored.ref, canonicalSha256(data));
  assert.deepEqual(decodeVerifierParentDomainDispatchClosure(await artifacts.readCanonical(stored.ref)), data);
  for (const change of [
    { ...data, additional: true }, { ...data, closure: { ...data.closure, childDead: true } },
    { ...data, closure: { ...data.closure, kind: 'containment_death' } },
    { ...data, closure: { ...data.closure, controllerLifetime: 'alive' } },
    { ...data, closure: { ...data.closure, claimingStateOwnerEpoch: 0 } },
    { ...data, closure: { ...data.closure, leaseEpoch: 0 } },
    { ...data, closure: { ...data.closure, requestRef: 'not-a-reference' } },
    { ...data, closure: { ...data.closure, claimJournalSeq: 3 } },
    { ...data, observedAt: 'yesterday' },
  ]) {
    const changed = { ...change, evidenceDigest: '' };
    changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest');
    assert.throws(() => decodeVerifierParentDomainDispatchClosure(changed as VerifierParentDomainDispatchClosureV1));
  }
  let invoked = false;
  for (const candidate of [data, {}, { assertCurrent() { invoked = true; }, containment: {} }])
    assert.throws(() => readNativeRetainedWorkerRetirement(candidate as never), /invalid native retained worker retirement/u);
  assert.equal(invoked, false, 'data/callback cannot mint the genuine physical retirement owner');
});

async function sourceFunction(fileName: string, name: string) {
  const source = await readFile(new URL(fileName, import.meta.url), 'utf8');
  const parsed = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert(declaration?.body); return { parsed, declaration };
}

test('production UNKNOWN acceptance still acquires the actual SQL owner and complete progress before the shared data validator', async () => {
  const { parsed, declaration } = await sourceFunction('./verifier-unknown-retirement.ts', 'originalClaim');
  const calls: string[] = [];
  const visit = (node: ts.Node) => { if (ts.isCallExpression(node)) calls.push(node.expression.getText(parsed)); ts.forEachChild(node, visit); };
  visit(declaration);
  assert(calls.includes('readStateOwner') && calls.includes('readVerifierProgress') && calls.includes('validateVerifierUnknownOriginalClaim'));
  const returned = declaration.body!.statements.find((node): node is ts.ReturnStatement => ts.isReturnStatement(node)); assert(returned?.expression);
  let actual: unknown[] = [];
  const invoke = new Function('validateVerifierUnknownOriginalClaim', 'artifacts', 'cut', 'generation', 'launch', 'issuer', 'progress',
    ts.transpile(`return ${returned.expression.getText(parsed)};`, { target: ts.ScriptTarget.ES2022 }));
  const values = Array.from({ length: 6 }, (_, index) => ({ inertData: index }));
  invoke((...args: unknown[]) => { actual = args; }, ...values); assert.deepEqual(actual, values);
});

test('the actual private entry selects this UNKNOWN owner and real CAS target after older settled verifier attempts', async t => {
  // Only entry selection executes. The terminal validator deliberately throws
  // before any successful Run/native validation; callbacks record data only.
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-verifier-original-selection-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(directory));
  const oldTarget = (await artifacts.publishCanonical({ candidateItemId: 'inert-older-candidate' }, 'inert-target')).ref;
  const selectedTarget = (await artifacts.publishCanonical({ candidateItemId: 'inert-current-candidate' }, 'inert-target')).ref;
  const { declaration } = await sourceFunction('./verifier-unknown-retirement.ts', 'originalClaim');
  const execute = new Function('hasOnlySettledVerifierUnknowns', 'readStateOwner', 'readCanonicalArtifact', 'readVerifierProgress', 'validateVerifierUnknownOriginalClaim',
    ts.transpile(`return (${declaration.getText()});`, { target: ts.ScriptTarget.ES2022 }));
  for (const phase of ['completed', 'failed'] as const) for (const sameOperation of [false, true]) {
    const older = journal().map(row => ({ ...row, target: oldTarget })); older[2]!.phase = phase;
    const selected = journal().map(row => ({ ...row, seq: row.seq + 3, target: selectedTarget, stateOwnerEpoch: 2,
      opId: sameOperation ? row.opId : 'inert-later-verifier', attempt: sameOperation ? 1 : 0 }));
    const cut = { journal: [...older, ...selected] }; assert.equal(hasOnlySettledVerifierUnknowns(cut.journal), true);
    const observed: Array<unknown[]> = [], sentinel = new Error('data-only validation boundary');
    const entry = execute(hasOnlySettledVerifierUnknowns,
      (driver: unknown, epoch: number) => { observed.push(['owner', epoch]); return { inertEpoch: epoch }; },
      (catalog: ArtifactCatalog, ref: string) => catalog.readCanonical(ref),
      async (driver: unknown, catalog: ArtifactCatalog, actualCut: unknown, candidateItemId: string) => {
        assert.equal(actualCut, cut); observed.push(['progress', candidateItemId]); return { inertProgress: candidateItemId };
      }, (...args: unknown[]) => { observed.push(['validator', args[4], args[5]]); throw sentinel; });
    await assert.rejects(entry(undefined, artifacts, cut, {}, {}), error => error === sentinel);
    assert.deepEqual(observed, [['owner', 2], ['progress', 'inert-current-candidate'],
      ['validator', { inertEpoch: 2 }, { inertProgress: 'inert-current-candidate' }]], `${phase}/${sameOperation}`);
  }
});

test('the actual original-child predicate rejects a changed request, grant, child plan, parent, generation or controller lifetime', async () => {
  const { parsed, declaration } = await sourceFunction('./verifier-unknown-retirement.ts', 'validateVerifierUnknownOriginalClaim');
  const condition = declaration.body!.statements.find((node): node is ts.IfStatement => ts.isIfStatement(node) &&
    node.thenStatement.getText(parsed).includes('verifier UNKNOWN is not confined to its exact retired parent domain'));
  assert(condition);
  const expression = ts.transpile(`return (${condition.expression.getText(parsed)});`, { target: ts.ScriptTarget.ES2022 });
  const refuses = new Function('spec', 'prepared', 'request', 'target', 'launch', 'plan', 'generation', 'cut', 'issuer', 'parent',
    'parentSpec', 'claim', 'path', 'canonicalSha256', 'identityHash', expression);
  const cgroupDigest = canonicalSha256(['cliq-verifier-cgroup-v1', 'data-dispatch']);
  const data = { spec: { requestRef: ref('a'), requestDigest: ref('b'), targetRef: ref('c'), targetDigest: ref('d'), operationGrantRef: ref('e'),
      parentWorkerContainmentRef: ref('f'), containmentPlanDigest: ref('1'), filesystem: { kind: 'run_generation', generationRef: ref('2'), sourceProjectionRef: ref('3') },
      runtime: { runtimeBundleRef: ref('4'), runtimeBundleManifestDigest: ref('5') }, sandboxProfileRef: ref('7'), sandboxProfileDigest: ref('8'),
      createdAt: '2026-10-25T00:00:01.000Z' },
    prepared: { requestRef: ref('a'), target: ref('c'), grantRef: ref('e'), timestamp: '2026-10-25T00:00:00.000Z' },
    request: { requestDigest: ref('b') }, target: { targetDigest: ref('d') },
    launch: { processContainmentRef: ref('f') }, plan: { parentContainmentRef: ref('f'), planDigest: ref('1'),
      createdAt: '2026-10-25T00:00:01.000Z', backend: { kind: 'linux', cgroupPath: `/private-parent/cliq-${cgroupDigest}`,
        subreaperStartToken: 'data-original-controller', cgroupNameReservationDigest: cgroupDigest,
        pidNamespaceReservationId: identityHash('cliq-verifier-namespace-v1', 'data-dispatch') } },
    generation: { generationRef: ref('2') }, cut: { runSpec: { sourceProjectionRef: ref('3') } },
    issuer: { runtimeBundleRef: ref('4'), runtimeBundleManifestDigest: ref('5') },
    parent: { backend: { kind: 'linux', cgroupPath: '/private-parent', subreaperStartToken: 'data-original-controller' } },
    parentSpec: { sandboxProfileRef: ref('7'), sandboxProfileDigest: ref('8') },
    claim: { timestamp: '2026-10-25T00:00:02.000Z', dispatchId: 'data-dispatch' } };
  const run = (values: typeof data) => refuses(...Object.values(values), path, canonicalSha256, identityHash);
  assert.equal(run(data), false);
  for (const [record, member] of [['spec', 'requestRef'], ['spec', 'requestDigest'], ['spec', 'operationGrantRef'],
    ['spec', 'parentWorkerContainmentRef'], ['launch', 'processContainmentRef'], ['plan', 'parentContainmentRef'],
    ['plan', 'planDigest'], ['generation', 'generationRef'], ['issuer', 'runtimeBundleRef']] as const) {
    const changed = structuredClone(data); (changed[record] as Record<string, unknown>)[member] = ref('9');
    assert.equal(run(changed), true, `${record}.${member}`);
  }
  for (const [key, value] of [['cgroupPath', '/another-parent/child'], ['subreaperStartToken', 'data-other-controller']] as const) {
    const changed = structuredClone(data); changed.plan.backend[key] = value;
    assert.equal(run(changed), true, key);
  }
});

test('the actual child and parent owner comparisons reject replaced claim, dispatch, lease or worker identities', async () => {
  const { parsed, declaration } = await sourceFunction('./verifier-unknown-retirement.ts', 'validateVerifierUnknownOriginalClaim');
  const owner = declaration.body!.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations
    .some(entry => entry.name.getText(parsed) === 'owner'));
  const comparisons = declaration.body!.statements.filter(node => ts.isExpressionStatement(node) &&
    ts.isCallExpression(node.expression) && node.expression.expression.getText(parsed) === 'requireEqual' &&
    ['abandoned verifier child owner', 'abandoned verifier child plan', 'abandoned verifier exact parent']
      .includes((node.expression.arguments[2] as ts.StringLiteral).text));
  assert(owner); assert.equal(comparisons.length, 3);
  const output = ts.transpile(`${owner.getText(parsed)}; ${comparisons.map(node => node.getText(parsed)).join('\n')}`,
    { target: ts.ScriptTarget.ES2022 });
  const compare = new Function('cut', 'claim', 'launch', 'spec', 'plan', 'parent', 'requireEqual', output);
  const cut = { run: { id: 'inert-run-id' } }, claim = { leaseEpoch: 2, opId: 'inert-op-id', attempt: 0, dispatchId: 'inert-dispatch-id' },
    launch = { launchId: 'inert-parent-id' }, original = { kind: 'run_invocation', runId: 'inert-run-id', intendedLeaseEpoch: 2,
      workerLaunchId: 'inert-parent-id', opId: 'inert-op-id', attempt: 0, dispatchId: 'inert-dispatch-id' },
    parent = { owner: { kind: 'worker_activation', runId: 'inert-run-id', intendedLeaseEpoch: 2, workerLaunchId: 'inert-parent-id' } };
  assert.doesNotThrow(() => compare(cut, claim, launch, { owner: original }, { owner: original }, parent, requireEqual));
  for (const [member, value] of [['runId', 'another'], ['workerLaunchId', 'another'], ['opId', 'another'],
    ['dispatchId', 'another'], ['intendedLeaseEpoch', 3], ['attempt', 1]] as const) {
    assert.throws(() => compare(cut, claim, launch, { owner: { ...original, [member]: value } }, { owner: original }, parent, requireEqual));
    assert.throws(() => compare(cut, claim, launch, { owner: original }, { owner: { ...original, [member]: value } }, parent, requireEqual));
  }
  assert.throws(() => compare(cut, claim, launch, { owner: original }, { owner: original },
    { owner: { ...parent.owner, intendedLeaseEpoch: 3 } }, requireEqual));
});

test('the actual original claiming-epoch predicate rejects unknown, foreign, future and already-released issuers', async () => {
  const { parsed, declaration } = await sourceFunction('./verifier-unknown-retirement.ts', 'validateVerifierUnknownOriginalClaim');
  const condition = declaration.body!.statements.find((node): node is ts.IfStatement => ts.isIfStatement(node) &&
    node.thenStatement.getText(parsed).includes('verifier UNKNOWN has a foreign claiming owner'));
  assert(condition);
  const output = ts.transpile(`return !!(${condition.expression.getText(parsed)});`, { target: ts.ScriptTarget.ES2022 });
  const refuses = new Function('issuer', 'claim', output), claim = { supervisorInstanceId: 'inert-supervisor-id', timestamp: '2026-10-25T00:00:01.000Z' };
  const issuer = { supervisorInstanceId: 'inert-supervisor-id', acquiredAt: '2026-10-25T00:00:00.000Z', state: 'active' };
  assert.equal(refuses(issuer, claim), false);
  for (const changed of [undefined, { ...issuer, supervisorInstanceId: 'foreign' },
    { ...issuer, acquiredAt: '2026-10-25T00:00:02.000Z' },
    { ...issuer, state: 'terminal', releasedAt: '2026-10-25T00:00:00.500Z' }]) assert.equal(refuses(changed, claim), true);
});

test('the terminal writer can consume verifier UNKNOWN only through its original opaque worker-recovery plan', async () => {
  for (const token of [{}, closureData(), { verifierAbandoned: [{}] }])
    assert.throws(() => readWorkerRecoveryTerminalPlan(undefined as never, undefined as never, token as never, 'inert-run-id'),
      { code: 'ARTIFACT_MISMATCH' });
  const source = await readFile(new URL('./reducers/stop.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('stop.ts', source, ts.ScriptTarget.Latest, true);
  const candidates: ts.IfStatement[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.expression.getText(parsed).includes('workerRecovery?.verifierAbandoned.some')) candidates.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(candidates.length, 1);
  const expression = ts.transpile(`return !!(${candidates[0]!.expression.getText(parsed)});`, { target: ts.ScriptTarget.ES2022 });
  const accepted = new Function('entry', 'workerRecovery', expression), unknown = journal()[2]!;
  const match = { opId: unknown.opId, attempt: unknown.attempt, unknownJournalSeq: unknown.seq,
    budgetSettlementRef: unknown.budgetSettlementRef, dispatchFenceOrDeathEvidenceRef: ref('1') };
  assert.equal(accepted(unknown, undefined), false);
  assert.equal(accepted(unknown, { verifierAbandoned: [] }), false);
  assert.equal(accepted(unknown, { verifierAbandoned: [match] }), true);
  for (const changed of [{ ...match, opId: 'another' }, { ...match, attempt: 1 },
    { ...match, unknownJournalSeq: 4 }, { ...match, budgetSettlementRef: ref('2') }])
    assert.equal(accepted(unknown, { verifierAbandoned: [changed] }), false);
});

test('the actual worker-retirement observation rejects structural or live data before any workspace or SQL access', async () => {
  const { parsed, declaration } = await sourceFunction('./worker-recovery-terminal.ts', 'prepareWorkerRecoveryTerminalPlan');
  const observations = declaration.body!.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'observeNativeOwners');
  assert(observations?.body);
  const output = ts.transpile(`${observations.getText(parsed)}; return observeNativeOwners;`, { target: ts.ScriptTarget.ES2022 });
  let accessed = false;
  const observe = new Function('input', 'readNativeRetainedWorkerRetirement', 'readRetainedWorkspaceRetirement', 'owner', output)(
    { nativeRetirement: closureData() }, readNativeRetainedWorkerRetirement, () => { accessed = true; }, {});
  assert.throws(observe, /invalid native retained worker retirement/u);
  assert.equal(accessed, false);
});

test('known received verifier results still bypass the UNKNOWN catch, without changing their original completion', async () => {
  const source = await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('run-execution.ts', source, ts.ScriptTarget.Latest, true);
  const conditions: ts.IfStatement[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.expression.getText(parsed) === "claimedVerifier && operationPhase !== 'received'") conditions.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(conditions.length, 1);
  const output = ts.transpile(`return !!(${conditions[0]!.expression.getText(parsed)});`, { target: ts.ScriptTarget.ES2022 });
  const becomesUnknown = new Function('claimedVerifier', 'operationPhase', output);
  assert.equal(becomesUnknown({}, 'received'), false);
  assert.equal(becomesUnknown({}, 'claimed'), true);
  assert.equal(becomesUnknown(undefined, 'claimed'), false);
});

test('retained parent-domain acceptance independently rewalks the physical quarantine even at equal-millisecond retirement cuts', async () => {
  const { parsed, declaration } = await sourceFunction('./verifier-unknown-retirement.ts', 'validateVerifierUnknownTerminalHistory');
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'validateRetainedWorkerQuarantines') calls.push(node);
    ts.forEachChild(node, visit);
  };
  visit(declaration); assert.equal(calls.length, 1);
  // Execute the actual data argument construction. The callback below records
  // inert input only, not an implementation of physical validation.
  const output = ts.transpile(`return (async () => ${calls[0]!.getText(parsed)})();`, { target: ts.ScriptTarget.ES2022 });
  const actual = new Function('validateRetainedWorkerQuarantines', 'artifacts', 'cut', 'launch', 'retired', 'driver', output);
  const data = { run: { id: 'inert-retained-row' }, journal: [{ seq: 3 }] }, launch = { launchId: 'inert-parent-row' },
    retired = { source: { phase: 'quarantined', generationRef: ref('a') } };
  let observed: unknown;
  await actual((_artifacts: unknown, value: unknown) => { observed = value; }, undefined, data, launch, retired, undefined);
  assert.deepEqual(observed, { run: data.run, journal: data.journal, workerLaunches: [launch], workspaceGenerations: [retired.source] });
});

/** Execute only the actual retained-source reads and association predicate.
 * With the VC1 omission this is the empty data fragment and a substituted
 * candidate is not refused. No missing guard is supplied by this test. */
async function generationSourceBinding() {
  const { parsed, declaration } = await sourceFunction('./verifier-unknown-retirement.ts', 'validateVerifierUnknownOriginalClaim');
  const reads = declaration.body!.statements.filter(node => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(entry => ['resultSource', 'state', 'projected'].includes(entry.name.getText(parsed))));
  const predicates = declaration.body!.statements.filter(node => ts.isIfStatement(node) &&
    node.thenStatement.getText(parsed).includes('verifier UNKNOWN generation source differs from its exact candidate'));
  assert(reads.length === 0 || reads.length === 3); assert(predicates.length <= 1);
  const output = ts.transpile(`return (async () => { ${reads.map(node => node.getText(parsed)).join('\n')}
    ${predicates.map(node => node.getText(parsed)).join('\n')} })();`, { target: ts.ScriptTarget.ES2022 });
  return new Function('artifacts', 'cut', 'generation', 'target', 'progress', 'readCanonicalArtifact',
    'decodeSourceManifest', 'decodeWorkspaceState', 'readCandidateSource', output);
}

test('the exact retained generation rejects another self-consistent same-Run candidate through real source CAS, not a live workspace', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-verifier-source-association-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
  const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
    frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [],
    maxChangedPaths: 10, maxChangedBytes: 1024, projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionRef = (await artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
  const empty: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [], entryCount: 0,
    byteCount: 0, treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [] }) };
  const emptyRef = (await artifacts.publishCanonical(empty, empty.format)).ref;
  const base: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base', workspaceIdentityDigest: ref('a'),
    entriesRef: emptyRef, sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
    frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: empty.treeDigest, manifestDigest: '' };
  base.manifestDigest = digestOmitting(base, 'manifestDigest');
  const baseRef = (await artifacts.publishCanonical(base, base.format)).ref;
  // These two ordinary recipe fields are consumed only by the real immutable
  // data reader. This creates no admitted RunSpec, Run, owner or native proof.
  const recipe = { baseWorkspaceManifestRef: baseRef, sourceProjectionRef: projectionRef } as RunSpec;
  async function source(bytes: string) {
    const blob = await artifacts.publishBytes(Buffer.from(bytes), 'application/octet-stream', 'inert-source-bytes');
    const entries: WorkspaceEntryManifest = { ...empty, entries: [{ path: 'value', kind: 'file', mode: 0o644,
      blobRef: blob.ref, size: Buffer.byteLength(bytes) }], entryCount: 1, byteCount: Buffer.byteLength(bytes), treeDigest: '' };
    entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
    const entriesRef = (await artifacts.publishCanonical(entries, entries.format)).ref;
    const state: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: 'inert-same-run',
      baseWorkspaceManifestRef: baseRef, entriesRef, invalidatedEphemeralPaths: [], sourceProjectionDigest: projection.projectionDigest, stateDigest: '' };
    state.stateDigest = digestOmitting(state, 'stateDigest');
    const stateRef = (await artifacts.publishCanonical(state, state.format)).ref;
    const projected = await readCandidateSource(artifacts, recipe, stateRef);
    assert.equal((await artifacts.publishCanonical(projected.source, projected.source.format)).ref, projected.sourceRef);
    return { state, stateRef, projected, blobRef: blob.ref };
  }
  const physical = await source('alpha'), other = await source('bravo'), check = await generationSourceBinding();
  const cut = { run: { id: 'inert-same-run' }, runSpec: recipe }, generation = { sourceWorkspaceStateRef: physical.stateRef };
  const candidate = (value: typeof physical) => ({ resultSourceRef: value.projected.sourceRef, sourceDigest: value.projected.source.manifestDigest });
  const invoke = (target = candidate(physical), progress = { candidate: candidate(physical) }, selected = generation) => check(artifacts, cut, selected, target, progress,
    (catalog: ArtifactCatalog, artifactRef: string) => catalog.readCanonical(artifactRef), decodeSourceManifest, decodeWorkspaceState, readCandidateSource);
  await invoke();
  assert.notEqual(physical.projected.sourceRef, other.projected.sourceRef);
  await assert.rejects(invoke(candidate(other), { candidate: candidate(other) }),
    /verifier UNKNOWN generation source differs from its exact candidate/u);
  await assert.rejects(invoke({ ...candidate(physical), sourceDigest: other.projected.source.manifestDigest },
    { candidate: { ...candidate(physical), sourceDigest: other.projected.source.manifestDigest } }),
  /verifier UNKNOWN generation source differs from its exact candidate/u);
  await assert.rejects(invoke(candidate(physical), { candidate: candidate(other) }),
    /verifier UNKNOWN generation source differs from its exact candidate/u);
  for (const [field, value] of [['sourceProjectionRef', ref('b')], ['sourceProjectionDigest', ref('c')], ['role', 'base']] as const) {
    const substituted = { ...physical.projected.source, [field]: value, manifestDigest: '' };
    substituted.manifestDigest = digestOmitting(substituted, 'manifestDigest');
    const stored = await artifacts.publishCanonical(substituted, substituted.format);
    const target = { resultSourceRef: stored.ref, sourceDigest: substituted.manifestDigest };
    await assert.rejects(invoke(target, { candidate: target }), /verifier UNKNOWN generation source differs from its exact candidate/u);
  }
  const foreignState = { ...physical.state, runId: 'inert-another-run', stateDigest: '' };
  foreignState.stateDigest = digestOmitting(foreignState, 'stateDigest');
  const foreignStateRef = (await artifacts.publishCanonical(foreignState, foreignState.format)).ref;
  // Same entries/projection give the same result manifest; only the actual
  // original source-state Run association distinguishes this bad graph.
  assert.equal((await readCandidateSource(artifacts, recipe, foreignStateRef)).sourceRef, physical.projected.sourceRef);
  await assert.rejects(invoke(candidate(physical), { candidate: candidate(physical) }, { sourceWorkspaceStateRef: foreignStateRef }),
    /verifier UNKNOWN generation source differs from its exact candidate/u);
});
