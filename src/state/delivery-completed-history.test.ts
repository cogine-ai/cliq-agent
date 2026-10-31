// Execute the actual private read-family functions over genuine CAS and
// ordinary SQLite records. The preceding graph nodes below are inert JSON,
// not Run/StateOwner/native evidence or an installed qualification bypass.
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test, type TestContext } from 'node:test';
import { Script } from 'node:vm';
import ts from 'typescript';
import { canonicalSha256 } from '../kernel/canonical.js';
import { immutableSnapshot } from '../model/immutable.js';
import { stopInvocationHistory } from '../runtime/stop.js';
import { isZeroBudget } from './invariants.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

type Value = Record<string, unknown>;
type Cut = { run: { id: string; sessionId: string; latestCheckpointId: string; revision: number; [key: string]: unknown };
  runSpec: { operation: string; [key: string]: unknown }; latestCheckpoint: Value; items: Value[]; journal: Value[];
  workerLaunches: Value[]; workspaceGenerations: Value[]; childAllocations: Value[] };
type Input = { driver: unknown; artifacts: ArtifactCatalog; run: Cut['run']; spec: Cut['runSpec'];
  items: Value[]; journal: Value[] };
type Nodes = { admission(): Promise<unknown>; merges(): Promise<unknown>; basis(): Promise<Value> };
type Api = {
  validateAgentRecoveryInDeliveryResultEpoch(input: Input, cut: Cut, data: Nodes): Promise<{ repairAttempts: number; data: object }>;
  validateAgentRecoveryInDeliveryEpoch(input: Input, data: Nodes): Promise<{ repairAttempts: number }>;
  readAgentRecoveryData(driver: unknown, reads: ArtifactCatalog, cut: Cut, token: unknown): unknown;
  createDeliveryReadData(driver: unknown, reads: ArtifactCatalog, cut: Cut): Nodes;
  completeDeliveryRecoveryHistory(driver: unknown, reads: ArtifactCatalog, cut: Cut, data: Nodes, token: unknown): void;
  closeDeliveryReadData(driver: unknown, reads: ArtifactCatalog, cut: Cut, data: Nodes): void;
  readResultBasisInDeliveryEpoch(driver: unknown, reads: ArtifactCatalog, cut: Cut, data: Nodes): Promise<Value>;
};

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

test('Delivery reuses only its completed original progress and preserves independent fresh basis reads', async t => {
  const f = await fixture(t), original = await f.open();
  const basis = await original.data.basis();
  assert.equal(await original.data.basis(), basis);
  assert.equal(f.independentProgressReads(), 0);
  assert.deepEqual(f.calls, ['admission', 'merge', 'item', 'progress', 'summary', 'basis']);
  const fresh = f.api.createDeliveryReadData(f.driver, f.artifacts, structuredClone(f.cut));
  await fresh.basis();
  assert.equal(f.independentProgressReads(), 1, 'an independent reader still reads actual progress bytes');
  assert.equal(f.calls.filter(value => value === 'progress').length, 2);
});

test('a structural family, fabricated progress or a token from another actual family cannot supply history', async t => {
  const f = await fixture(t), original = await f.open();
  const other = f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut);
  const fake = { admission: async () => ({}), merges: async () => new Map(), basis: async () => ({}) };
  await assert.rejects(f.api.validateAgentRecoveryInDeliveryResultEpoch(f.input(), f.cut, fake), /exact original read family/);
  for (const token of [{}, new Map(), { ...original.history.data }])
    assert.throws(() => f.api.completeDeliveryRecoveryHistory(f.driver, f.artifacts, f.cut, original.data, token));
  assert.throws(() => f.api.completeDeliveryRecoveryHistory(f.driver, f.artifacts, f.cut, other, original.history.data), /another family/);
  assert.equal(f.independentProgressReads(), 0);
});

test('unfinished history is not usable and cannot be attached retroactively after a basis already ran', async t => {
  const f = await fixture(t), entered = gate(), release = gate();
  f.hooks.history = async input => {
    entered.release(); await release.promise;
    return { repairAttempts: 0, decodedItems: new Map(), verifierProgressByCandidate: new Map([
      ['inert-candidate', await readCanonicalArtifact(input.artifacts, f.refs.progress!)]
    ]) };
  };
  const data = f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut);
  const pending = f.api.validateAgentRecoveryInDeliveryResultEpoch(f.input(), f.cut, data);
  await entered.promise;
  assert.throws(() => f.api.completeDeliveryRecoveryHistory(f.driver, f.artifacts, f.cut, data, {}));
  await data.basis();
  assert.equal(f.independentProgressReads(), 1, 'no completed token means the original fresh reader');
  release.release(); const completed = await pending;
  assert.throws(() => f.api.completeDeliveryRecoveryHistory(f.driver, f.artifacts, f.cut, data, completed.data), /precede its first result basis/);
});

test('live worker cuts retain the original validator and cannot mint the stronger worker-free sharing token', async t => {
  const f = await fixture(t), data = f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut);
  (f.cut.run as typeof f.cut.run & { activeWorkerLaunchId?: string }).activeWorkerLaunchId = 'inert-live-worker';
  await assert.rejects(f.api.validateAgentRecoveryInDeliveryResultEpoch(f.input(), f.cut, data), /original recovery cut/);
  delete (f.cut.run as typeof f.cut.run & { activeWorkerLaunchId?: string }).activeWorkerLaunchId;
  f.cut.workerLaunches.push({ phase: 'active', leaseVersion: 1 });
  await assert.rejects(f.api.validateAgentRecoveryInDeliveryResultEpoch(f.input(), f.cut, data), /original recovery cut/);
  assert.deepEqual(f.calls, []);
  assert.deepEqual(await f.api.validateAgentRecoveryInDeliveryEpoch(f.input(), data), { repairAttempts: 0 });
  assert.equal(f.calls.filter(value => value === 'progress').length, 1);
});

test('completed Delivery data still rejects changed retired launch rows on a cached basis hit', async t => {
  const f = await fixture(t), original = await f.open(); await original.data.basis();
  f.write('launches', f.cut.run.id, [{ phase: 'retired', original: false }]);
  await assert.rejects(original.data.basis(), /SQL changed/);
  assert.equal(f.independentProgressReads(), 0);
});

test('completed Delivery data still checks the original source Run and Session on cached hits', async t => {
  const f = await fixture(t), original = await f.open(); await original.data.basis();
  f.write('run', 'inert-source-run', { id: 'inert-source-run', revision: 3 });
  await assert.rejects(original.data.basis(), /original source\/Session changed/);
});

test('closing after cancellation invalidates the token, family and captured callbacks without claiming resource retirement', async t => {
  const f = await fixture(t), abort = new AbortController(), reads = f.artifacts.withReadSignal(abort.signal);
  const original = await f.open(f.cut, reads), basis = original.data.basis;
  await basis(); const reason = new Error('inert data read cancelled'); abort.abort(reason);
  await assert.rejects(basis(), error => error === reason);
  f.api.closeDeliveryReadData(f.driver, reads, f.cut, original.data);
  await assert.rejects(basis(), /scope is closed/);
  assert.throws(() => f.api.completeDeliveryRecoveryHistory(f.driver, reads, f.cut, original.data, original.history.data));
  assert.throws(() => f.api.closeDeliveryReadData(f.driver, reads, f.cut, original.data));
});

test('the next completed Delivery entry reopens real CAS and rejects changed progress bytes', async t => {
  const f = await fixture(t), one = await f.open(); await one.data.basis();
  f.api.closeDeliveryReadData(f.driver, f.artifacts, f.cut, one.data);
  assert.throws(() => f.api.readAgentRecoveryData(f.driver, f.artifacts, f.cut, one.history.data));
  const file = path.join(f.root, f.refs.progress!), before = await readFile(file);
  await chmod(file, 0o600); await writeFile(file, Buffer.alloc(before.length, 0x20)); await chmod(file, 0o400);
  try { await assert.rejects(f.open(structuredClone(f.cut)), /corrupt|digest/u); }
  finally { await chmod(file, 0o600); await writeFile(file, before); await chmod(file, 0o400); }
  const two = await f.open(structuredClone(f.cut)); assert.notEqual(await two.data.basis(), await f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut).basis());
});

test('failed original history joins every issued real CAS reader and preserves retirement failure before sharing', async t => {
  const f = await fixture(t), entered = gate(), release = gate();
  let issued = 0, settled = false;
  const ordinary = new Error('inert ordinary read failure'), retirement = new ResourceRetirementError('inert retirement failure', ordinary);
  f.hooks.history = input => input.artifacts.mapReads([0, 1], async index => {
    if (++issued === 2) entered.release(); await release.promise;
    await readCanonicalArtifact(input.artifacts, f.refs.progress!);
    throw index === 0 ? ordinary : retirement;
  });
  const data = f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut);
  const pending = f.api.validateAgentRecoveryInDeliveryResultEpoch(f.input(), f.cut, data);
  void pending.then(() => { settled = true; }, () => { settled = true; });
  await entered.promise; await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(settled, false); assert.equal(issued, 2);
  release.release(); await assert.rejects(pending, error => error === retirement);
  assert.throws(() => f.api.completeDeliveryRecoveryHistory(f.driver, f.artifacts, f.cut, data, {}));
  f.api.closeDeliveryReadData(f.driver, f.artifacts, f.cut, data);
});

test('the actual recovery selector leaves live cuts on the original reader and its finally expires Delivery callbacks', async t => {
  const f = await fixture(t), original = await f.open(); await original.data.basis();
  const parsed = ts.createSourceFile('recovery-closure.ts', await readFile(new URL('./recovery-closure.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'readRecoveryProjection');
  assert(declaration?.body);
  const selectors: ts.IfStatement[] = [], finalizers: ts.Block[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.expression.getText(parsed) === '!run.activeWorkerLaunchId && workerLaunches.length === 0' &&
        node.thenStatement.getText(parsed).includes('validateAgentRecoveryInDeliveryResultEpoch')) selectors.push(node);
    if (ts.isTryStatement(node) && node.finallyBlock?.getText(parsed).includes('closeDeliveryReadData')) finalizers.push(node.finallyBlock);
    ts.forEachChild(node, visit);
  };
  visit(declaration.body); assert.equal(selectors.length, 1); assert.equal(finalizers.length, 1);
  assert.match(selectors[0]!.elseStatement!.getText(parsed), /validateAgentRecoveryInDeliveryEpoch\(input, delivery,/u);
  const eligible = new Function('run', 'workerLaunches', `return ${selectors[0]!.expression.getText(parsed)}`);
  assert.equal(eligible({}, []), true); assert.equal(eligible({ activeWorkerLaunchId: 'live' }, []), false);
  assert.equal(eligible({}, [{ phase: 'active', leaseVersion: 2 }]), false);
  const marker = new Error('inert original entry failure');
  const close = new Function('delivery', 'driver', 'artifacts', 'closure', 'closeDeliveryReadData', 'marker',
    `try { throw marker; } finally ${finalizers[0]!.getText(parsed)}`);
  assert.throws(() => close(original.data, f.driver, f.artifacts, f.cut, f.api.closeDeliveryReadData, marker), error => error === marker);
  await assert.rejects(original.data.basis(), /scope is closed/);
  assert.throws(() => f.api.readAgentRecoveryData(f.driver, f.artifacts, f.cut, original.history.data));
});

async function functions(dependencies: Record<string, unknown>): Promise<Api> {
  const selections = [
    ['agent-recovery.ts', ['agentReadBrand', 'agentReadData', 'agentRecoverySqlCut',
      'validateCompletedRecoveryHistory', 'validateAgentRecoveryInDeliveryResultEpoch',
      'validateAgentRecoveryInDeliveryEpoch', 'readAgentRecoveryData', 'closeAgentRecoveryData']],
    ['delivery-read-data.ts', ['deliveryReadBindings', 'createDeliveryReadData', 'assertDeliveryReadData',
      'completeDeliveryRecoveryHistory', 'closeDeliveryReadData']],
    ['run-result-recovery.ts', ['readDeliveryCandidateMaterialData', 'readDeliveryResultData', 'readDeliveryResultDataInRecovery',
      'assertResultBasisCut', 'readResultBasisInDeliveryEpoch']]
  ] as const;
  const bodies: string[] = [];
  for (const [filename, names] of selections) {
    const source = ts.createSourceFile(filename, await readFile(new URL(`./${filename}`, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
    for (const name of names) {
      const selected = source.statements.filter(node => ts.isFunctionDeclaration(node) ? node.name?.text === name
        : ts.isVariableStatement(node) && node.declarationList.declarations.some(item => item.name.getText(source) === name));
      assert.equal(selected.length, 1, `execute the one original ${name}, not a copied test implementation`);
      bodies.push(selected[0]!.getText(source).replace(/^export\s+/u, ''));
    }
  }
  const names = Object.keys(dependencies);
  const output = ts.transpileModule(bodies.join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext } }).outputText;
  const create = new Script(`(function(${names.join(',')}) { ${output}; return {
    validateAgentRecoveryInDeliveryResultEpoch, validateAgentRecoveryInDeliveryEpoch, readAgentRecoveryData,
    createDeliveryReadData, completeDeliveryRecoveryHistory, closeDeliveryReadData, readResultBasisInDeliveryEpoch }; })`,
  { filename: 'actual-delivery-completed-history-expression.js' }).runInThisContext() as (...args: unknown[]) => Api;
  return create(...names.map(name => dependencies[name]));
}

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-delivery-completed-history-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const database = new DatabaseSync(':memory:'); t.after(() => database.close());
  database.exec('CREATE TABLE inert_records(kind TEXT NOT NULL,id TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(kind,id)) STRICT');
  const write = (kind: string, id: string, value: unknown) => database.prepare(
    'INSERT OR REPLACE INTO inert_records VALUES(?,?,?)').run(kind, id, JSON.stringify(value));
  const record = <T>(kind: string, id: string): T => {
    const row = database.prepare('SELECT value FROM inert_records WHERE kind=? AND id=?').get(kind, id);
    assert(row && typeof row.value === 'string', 'every cut observation comes from a real ordinary SQLite record');
    return JSON.parse(row.value) as T;
  };
  const run = { id: 'inert-result', sessionId: 'inert-session', latestCheckpointId: 'inert-checkpoint', revision: 1,
    budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
  const checkpoint = { id: run.latestCheckpointId, runId: run.id };
  const cut: Cut = { run, runSpec: { operation: 'delivery' }, latestCheckpoint: checkpoint, items: [], journal: [],
    workerLaunches: [], workspaceGenerations: [], childAllocations: [] };
  for (const [kind, id, value] of [
    ['run', 'inert-source-run', { id: 'inert-source-run', revision: 2 }],
    ['run', run.id, run], ['session', run.sessionId, { id: run.sessionId, workspaceIdentityRef: 'inert-workspace' }],
    ['principal', run.sessionId, 'inert-principal'], ['checkpoint', checkpoint.id, checkpoint],
    ['checkpoints', run.id, [{ id: checkpoint.id }]], ['items', run.id, []], ['journal', run.id, []],
    ['launches', run.id, [{ phase: 'retired', original: true }]], ['generations', run.id, []], ['allocations', run.id, []],
    ['admission', run.id, { principal_id: 'inert-principal', admission_key: 'inert-original', admission_method: 'run.apply', admission_request_id: 'inert-request' }]
  ] as const) write(kind, id, value);
  const driver = { prepare(sql: string) {
    if (sql === 'SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      return { all: (id: string) => record('items', id) };
    if (sql === 'SELECT id FROM checkpoints WHERE run_id=? ORDER BY rowid')
      return { all: (id: string) => record('checkpoints', id) };
    assert.match(sql.replace(/\s+/gu, ' '), /^SELECT principal_id,\s?admission_method,\s?admission_key,\s?admission_intent_digest,\s?admission_request_id FROM runs WHERE id=\?$/u);
    return { get: (id: string) => record('admission', id) };
  } };
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
  const refs: Record<string, string> = {};
  const summary = { kind: 'inert-summary', utf8: 'ordinary data, no result authority' };
  refs.summary = (await artifacts.publishCanonical(summary, 'inert-data')).ref;
  const candidate = { itemId: 'inert-candidate', summaryRef: refs.summary, resultSourceRef: 'inert-new-source' };
  const admission = { run, source: { run: { id: 'inert-source-run', revision: 2 },
    session: { id: run.sessionId, workspaceIdentityRef: 'inert-workspace' }, result: { resultSourceRef: 'inert-old-source' } },
    target: { workspaceIdentityRef: 'inert-workspace' } };
  for (const [name, value] of Object.entries({ item: { kind: 'inert-item' },
    progress: { kind: 'inert-progress', candidate, spec: { verifiers: [{ gate: 'required' }] }, plan: {}, planRef: 'inert-plan' },
    basis: { kind: 'inert-basis' }, admission, merge: { candidate, source: { summary } } }))
    refs[name] = (await artifacts.publishCanonical(value, 'inert-delivery-reader-data')).ref;
  cut.runSpec.assemblyRef = (await artifacts.publishCanonical({ kind: 'inert-assembly' }, 'inert-data')).ref;
  const calls: string[] = [], guards: string[] = [];
  const read = async (reads: ArtifactCatalog, kind: string) => {
    calls.push(kind); return readCanonicalArtifact<Value>(reads, refs[kind]!);
  };
  const hooks: { history?: (input: Input) => Promise<unknown> } = {};
  let api: Api, independentProgressReads = 0;
  const dependencies: Record<string, unknown> = {
    canonicalSha256, requireEqual, immutableSnapshot, KernelStorageError, isZeroBudget, stopInvocationHistory,
    readCanonicalArtifact,
    assertRetiredGenerationCut: () => { guards.push('retired-generation'); },
    decodeRetainedRunAssembly: (value: Value) => {
      assert.equal(value.kind, 'inert-assembly'); return { mcpServers: [] };
    },
    readRun: (_driver: unknown, id: string) => record('run', id),
    readSession: (_driver: unknown, id: string) => record('session', id),
    readSessionPrincipalId: (_driver: unknown, id: string) => record('principal', id),
    readCheckpoint: (_driver: unknown, id: string) => record('checkpoint', id),
    readInvocationJournal: (_driver: unknown, id: string) => record('journal', id),
    readWorkerLaunchesForRun: (_driver: unknown, id: string) => record('launches', id),
    readWorkspaceGenerationsForRun: (_driver: unknown, id: string) => record('generations', id),
    readChildAllocationsForRun: (_driver: unknown, id: string) => record('allocations', id),
    validateAgentRecoveryData: async (input: Input, _onPhase: unknown, delivery?: Nodes) => {
      if (delivery) await delivery.merges();
      if (hooks.history) return hooks.history(input);
      // Only the graph node is replaced. The actual factory still waits for
      // its completion before minting a token bound to its real CAS/SQL cut.
      const item = await read(input.artifacts, 'item'), progress = await read(input.artifacts, 'progress');
      return { repairAttempts: 0, decodedItems: new Map([['inert-item', item]]), verifierProgressByCandidate: new Map([['inert-candidate', progress]]) };
    },
    assertPublicationReadCut: async (_driver: unknown, reads: ArtifactCatalog, actual: Cut) => {
      reads.assertReadActive(); requireEqual(record('run', actual.run.id), actual.run, 'inert current SQL projection');
    },
    readDeliveryRunAdmission: async (_driver: unknown, reads: ArtifactCatalog) => read(reads, 'admission'),
    validateDeliveryRecoveryData: async (_driver: unknown, reads: ArtifactCatalog) => new Map([['inert-merge', await read(reads, 'merge')]]),
    assertDeliveryModelFreeCut: (actual: Cut) => { assert.equal(actual.runSpec.operation, 'delivery'); },
    assertDeliveryReadCut: (_driver: unknown, actual: Cut) => { requireEqual(record('run', actual.run.id), actual.run, 'inert SQL projection'); },
    readVerifierProgress: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, id: string) => {
      independentProgressReads++; assert.equal(id, candidate.itemId); return read(reads, 'progress');
    },
    readControlRequest: () => ({ kind: 'inert-original-data' }),
    readText: async (reads: ArtifactCatalog, ref: string) => { calls.push('summary'); return readCanonicalArtifact(reads, ref); },
    readDeliveryResultBasisData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, material: { progress: unknown }) => ({
      ...await read(reads, 'basis'), progress: material.progress
    })

  };
  api = await functions(dependencies);
  const input = (actual = cut, reads = artifacts): Input => ({ driver, artifacts: reads, run: actual.run,
    spec: actual.runSpec, items: actual.items, journal: actual.journal });
  const open = async (actual = cut, reads = artifacts) => {
    const data = api.createDeliveryReadData(driver, reads, actual);
    const history = await api.validateAgentRecoveryInDeliveryResultEpoch(input(actual, reads), actual, data);
    api.completeDeliveryRecoveryHistory(driver, reads, actual, data, history.data);
    return { data, history };
  };
  return { root, database, write, record, driver, cas, artifacts, refs, cut, calls, guards, hooks, api, open, input,
    independentProgressReads: () => independentProgressReads };

}



test('completed progress is selected by the original merge candidate rather than Map order and missing progress cannot fall back', async t => {
  const f = await fixture(t);
  f.hooks.history = async input => {
    const progress = await readCanonicalArtifact<Value>(input.artifacts, f.refs.progress!);
    return { repairAttempts: 0, decodedItems: new Map(), verifierProgressByCandidate: new Map([
      ['inert-candidate', progress], ['different-later-entry', { ...progress, candidate: { itemId: 'foreign-inert-candidate' } }]
    ]) };
  };
  const original = await f.open(), basis = await original.data.basis();
  assert.deepEqual((basis.progress as Value).candidate, (await f.artifacts.readCanonical<Value>(f.refs.progress!)).candidate);
  assert.equal(f.independentProgressReads(), 0);
  const missing = await fixture(t);
  missing.hooks.history = async () => ({ repairAttempts: 0, decodedItems: new Map(), verifierProgressByCandidate: new Map() });
  const incomplete = await missing.open();
  await assert.rejects(incomplete.data.basis(), /lost its exact completely validated candidate/);
  assert.equal(missing.independentProgressReads(), 0, 'missing completed data must not silently run another selection');
});


/** Execute the production completion wrapper and the exact private return /
 * finally tail. Earlier recovery nodes remain inert fixture data here; their
 * actual graph and resource validation is exercised by the existing suites. */
async function completionReader(f: Awaited<ReturnType<typeof fixture>>, data: Nodes, agent?: object) {
  const parsed = ts.createSourceFile('recovery-closure.ts', await readFile(new URL('./recovery-closure.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const select = (name: string) => {
    const declaration = parsed.statements.find((node): node is ts.FunctionDeclaration =>
      ts.isFunctionDeclaration(node) && node.name?.text === name);
    assert(declaration?.body); return declaration;
  };
  const projection = select('readRecoveryProjection'), wrapper = select('readResultRecoveryClosure');
  const original = projection.body!.statements.find((node): node is ts.TryStatement =>
    ts.isTryStatement(node) && !!node.finallyBlock?.getText(parsed).includes('closeDeliveryReadData'));
  assert(original?.finallyBlock);
  const finalReturn = original.tryBlock.statements.at(-1)!;
  assert(ts.isReturnStatement(finalReturn));
  const requested = original.tryBlock.statements.at(-2)!;
  assert(ts.isVariableStatement(requested) && requested.declarationList.declarations[0]?.name.getText(parsed) === 'basis');
  const body = `async function readRecoveryProjection(${projection.parameters.map(parameter => parameter.getText(parsed)).join(',')}) {
    try { ${requested.getText(parsed)} ${finalReturn.getText(parsed)} } finally ${original.finallyBlock.getText(parsed)}
  }
${wrapper.getText(parsed).replace(/^export\s+/u, '')}`;
  let independentReads = 0, agentReads = 0, agentCloses = 0;
  const dependencies = { closure: f.cut, delivery: agent ? undefined : data, publicationPrefix: undefined, agent,
    closeDeliveryReadData: f.api.closeDeliveryReadData,
    readResultBasisInDeliveryEpoch: f.api.readResultBasisInDeliveryEpoch,
    readResultBasis: async () => { independentReads++; return readCanonicalArtifact<Value>(f.artifacts, f.refs.basis!); },
    readAgentResultData: () => ({ basis: async () => { agentReads++; return readCanonicalArtifact<Value>(f.artifacts, f.refs.basis!); } }),
    closeAgentResultReadData: () => { agentCloses++; } };
  const names = Object.keys(dependencies);
  const output = ts.transpileModule(body, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const create = new Script(`(function(${names.join(',')}) { ${output}; return { readResultRecoveryClosure, readRecoveryProjection }; })`)
    .runInThisContext() as (...args: unknown[]) => {
      readResultRecoveryClosure(driver: unknown, artifacts: ArtifactCatalog, runId: string): Promise<{ cut: Cut; basis: Value }>;
      readRecoveryProjection(driver: unknown, artifacts: ArtifactCatalog, runId: string): Promise<{ cut: Cut; basis?: Value }>;
    };
  return { ...create(...Object.values(dependencies)), counts: () => ({ independentReads, agentReads, agentCloses }) };
}

test('the completion reader returns its already verified Delivery basis as plain data before closing the actual family', async t => {
  const f = await fixture(t), original = await f.open(), basis = await original.data.basis();
  const entry = await completionReader(f, original.data), result = await entry.readResultRecoveryClosure(f.driver, f.artifacts, f.cut.run.id);
  assert.equal(result.basis, basis); assert.equal(result.cut, f.cut);
  assert.deepEqual(entry.counts(), { independentReads: 0, agentReads: 0, agentCloses: 0 });
  assert.equal(f.calls.filter(value => value === 'basis').length, 1);
  assert.deepEqual(f.guards, ['retired-generation'], 'the full result predicate is still required before reuse');
  await assert.rejects(original.data.basis(), /scope is closed/);
  assert.equal(result.basis.kind, 'inert-basis', 'returned ordinary data remains usable after the family closes');
});

test('ordinary recovery does not demand a result basis from an early Delivery without a candidate', async t => {
  const f = await fixture(t), data = f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut);
  const entry = await completionReader(f, data), result = await entry.readRecoveryProjection(f.driver, f.artifacts, f.cut.run.id);
  assert.equal(result.basis, undefined); assert.deepEqual(f.calls, []); assert.deepEqual(f.guards, []);
  await assert.rejects(data.basis(), /scope is closed/);
});

for (const blocked of ['reserved', 'active_worker', 'wait', 'open_journal'] as const)
  test(`result-specific Delivery reuse preserves the original ${blocked} completion refusal and closes the family`, async t => {
    const f = await fixture(t);
    if (blocked === 'reserved') f.cut.run.budgetReserved = { modelTokens: 1, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
    if (blocked === 'active_worker') f.cut.run.activeWorkerLaunchId = 'inert-live-worker';
    if (blocked === 'wait') f.cut.run.waitingReason = 'reconciliation';
    if (blocked === 'open_journal') f.cut.journal.push({ opId: 'inert-open', attempt: 0, opKind: 'publish', phase: 'dispatch_claimed' });
    f.write('run', f.cut.run.id, f.cut.run);
    const data = f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut), entry = await completionReader(f, data);
    await assert.rejects(entry.readResultRecoveryClosure(f.driver, f.artifacts, f.cut.run.id), /complete worker-free root candidate closure/);
    assert.deepEqual(f.calls, [], 'a refused completion does not read or return a publication-only basis');
    assert.deepEqual(entry.counts(), { independentReads: 0, agentReads: 0, agentCloses: 0 });
    await assert.rejects(data.basis(), /scope is closed/);
  });

test('the result-specific Delivery friend rejects fabricated families before the completion predicate', async t => {
  const f = await fixture(t);
  await assert.rejects(f.api.readResultBasisInDeliveryEpoch(f.driver, f.artifacts, f.cut,
    { admission: async () => ({}), merges: async () => ({}), basis: async () => ({}) }), /exact original read family/);
  assert.deepEqual(f.calls, []); assert.deepEqual(f.guards, []);
});

test('Agent completion keeps its original reader path and closes the original data token', async t => {
  const f = await fixture(t), data = f.api.createDeliveryReadData(f.driver, f.artifacts, f.cut);
  const entry = await completionReader(f, data, {}), result = await entry.readResultRecoveryClosure(f.driver, f.artifacts, f.cut.run.id);
  assert.equal(result.basis.kind, 'inert-basis');
  assert.deepEqual(entry.counts(), { independentReads: 0, agentReads: 1, agentCloses: 1 });
  assert.deepEqual(f.guards, []);
  f.api.closeDeliveryReadData(f.driver, f.artifacts, f.cut, data);
});
