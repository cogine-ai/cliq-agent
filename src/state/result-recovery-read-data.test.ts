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
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

type Value = Record<string, unknown>;
type Cut = { run: { id: string; sessionId: string; latestCheckpointId: string; revision: number };
  runSpec: { operation: string }; latestCheckpoint: Value; items: Value[]; journal: Value[];
  workerLaunches: Value[]; workspaceGenerations: Value[]; childAllocations: Value[] };
type Input = { driver: unknown; artifacts: ArtifactCatalog; run: Cut['run']; spec: Cut['runSpec'];
  items: Value[]; journal: Value[] };
type Nodes = { basis(): Promise<Value> };
type Api = {
  validateAgentRecoveryInResultEpoch(input: Input, cut: Cut): Promise<{ repairAttempts: number; data: object }>;
  readAgentRecoveryData(driver: unknown, reads: ArtifactCatalog, cut: Cut, token: unknown): {
    decodedItems: ReadonlyMap<string, Value>; verifierProgressByCandidate: ReadonlyMap<string, Value> };
  createAgentResultReadData(driver: unknown, reads: ArtifactCatalog, cut: Cut, token: unknown): object;
  readAgentResultData(driver: unknown, reads: ArtifactCatalog, cut: Cut, token: unknown): Nodes;
  closeAgentRecoveryData(driver: unknown, reads: ArtifactCatalog, cut: Cut, token: unknown): void;
  closeAgentResultReadData(driver: unknown, reads: ArtifactCatalog, cut: Cut, token: unknown): void;
};

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

async function functions(dependencies: Record<string, unknown>): Promise<Api> {
  const selections = [
    ['agent-recovery.ts', ['agentReadBrand', 'agentReadData', 'agentRecoverySqlCut',
      'validateAgentRecoveryInResultEpoch', 'readAgentRecoveryData', 'closeAgentRecoveryData']],
    ['run-result-recovery.ts', ['resultReadBrand', 'resultReadData', 'createAgentResultReadData', 'readAgentResultData', 'closeAgentResultReadData']]
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
    validateAgentRecoveryInResultEpoch, readAgentRecoveryData, closeAgentRecoveryData,
    createAgentResultReadData, readAgentResultData, closeAgentResultReadData }; })`,
  { filename: 'actual-result-recovery-read-family-expression.js' }).runInThisContext() as (...args: unknown[]) => Api;
  return create(...names.map(name => dependencies[name]));
}

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-result-read-family-'));
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
  const run = { id: 'inert-result', sessionId: 'inert-session', latestCheckpointId: 'inert-checkpoint', revision: 1 };
  const checkpoint = { id: run.latestCheckpointId, runId: run.id };
  const cut: Cut = { run, runSpec: { operation: 'agent' }, latestCheckpoint: checkpoint, items: [], journal: [],
    workerLaunches: [], workspaceGenerations: [], childAllocations: [] };
  for (const [kind, id, value] of [
    ['run', run.id, run], ['session', run.sessionId, { id: run.sessionId, workspaceIdentityRef: 'inert-workspace' }],
    ['principal', run.sessionId, 'inert-principal'], ['checkpoint', checkpoint.id, checkpoint],
    ['checkpoints', run.id, [{ id: checkpoint.id }]], ['items', run.id, []], ['journal', run.id, []],
    ['launches', run.id, [{ phase: 'retired', original: true }]], ['generations', run.id, []], ['allocations', run.id, []],
    ['admission', run.id, { principal_id: 'inert-principal', admission_key: 'inert-original' }]
  ] as const) write(kind, id, value);
  const driver = { prepare(sql: string) {
    if (sql === 'SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      return { all: (id: string) => record('items', id) };
    if (sql === 'SELECT id FROM checkpoints WHERE run_id=? ORDER BY rowid')
      return { all: (id: string) => record('checkpoints', id) };
    assert.equal(sql, 'SELECT principal_id,admission_method,admission_key,admission_intent_digest,admission_request_id FROM runs WHERE id=?');
    return { get: (id: string) => record('admission', id) };
  } };
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
  const refs: Record<string, string> = {};
  for (const [name, value] of Object.entries({ item: { kind: 'inert-item' }, progress: { kind: 'inert-progress' }, basis: { kind: 'inert-basis' } }))
    refs[name] = (await artifacts.publishCanonical(value, 'inert-result-reader-data')).ref;
  const calls: string[] = [], guards: string[] = [];
  const read = async (reads: ArtifactCatalog, kind: string) => {
    calls.push(kind); return readCanonicalArtifact<Value>(reads, refs[kind]!);
  };
  const hooks: { history?: (input: Input) => Promise<unknown>; basis?: (reads: ArtifactCatalog, token: unknown) => Promise<Value> } = {};
  let api: Api;
  const dependencies: Record<string, unknown> = {
    canonicalSha256, requireEqual, immutableSnapshot, KernelStorageError,
    readRun: (_driver: unknown, id: string) => record('run', id),
    readSession: (_driver: unknown, id: string) => record('session', id),
    readSessionPrincipalId: (_driver: unknown, id: string) => record('principal', id),
    readCheckpoint: (_driver: unknown, id: string) => record('checkpoint', id),
    readInvocationJournal: (_driver: unknown, id: string) => record('journal', id),
    readWorkerLaunchesForRun: (_driver: unknown, id: string) => record('launches', id),
    readWorkspaceGenerationsForRun: (_driver: unknown, id: string) => record('generations', id),
    readChildAllocationsForRun: (_driver: unknown, id: string) => record('allocations', id),
    validateAgentRecoveryData: async (input: Input) => {
      if (hooks.history) return hooks.history(input);
      // Only the graph node is replaced. The actual factory still waits for
      // its completion before minting a token bound to its real CAS/SQL cut.
      const item = await read(input.artifacts, 'item'), progress = await read(input.artifacts, 'progress');
      return { repairAttempts: 0, decodedItems: new Map([['inert-item', item]]), verifierProgressByCandidate: new Map([['inert-candidate', progress]]) };
    },
    assertResultBasisCut: async (_driver: unknown, reads: ArtifactCatalog) => { reads.assertReadActive(); guards.push('basis-cut'); },
    readAgentResultBasis: async (_driver: unknown, reads: ArtifactCatalog, actual: Cut, token: unknown) => {
      if (hooks.basis) return hooks.basis(reads, token);
      const history = api.readAgentRecoveryData(driver, reads, actual, token);
      return { ...await read(reads, 'basis'), item: history.decodedItems.get('inert-item'),
        progress: history.verifierProgressByCandidate.get('inert-candidate') };
    }
  };
  api = await functions(dependencies);
  const open = async (actual = cut, reads = artifacts) => {
    const history = await api.validateAgentRecoveryInResultEpoch({ driver, artifacts: reads, run: actual.run, spec: actual.runSpec,
      items: actual.items, journal: actual.journal }, actual);
    const token = api.createAgentResultReadData(driver, reads, actual, history.data);
    return { history, token, data: api.readAgentResultData(driver, reads, actual, token) };
  };
  return { root, database, write, record, driver, cas, artifacts, refs, cut, calls, guards, hooks, api, open };
}

test('one actual read family shares completed history and basis through repeated consumers without accepting caller data', async t => {
  const f = await fixture(t), original = await f.open(), basis = await original.data.basis();
  assert.equal(await original.data.basis(), basis);
  assert.equal(await f.api.readAgentResultData(f.driver, f.artifacts, f.cut, original.token).basis(), basis);
  assert.deepEqual(f.calls, ['item', 'progress', 'basis']);
  assert.equal(f.guards.length, 3, 'the worker-free/current-cut predicate remains live on every hit');
  assert.equal(basis.item, f.api.readAgentRecoveryData(f.driver, f.artifacts, f.cut, original.history.data).decodedItems.get('inert-item'));
  for (const fake of [{}, new Map(), { basis: () => basis }, { ...original.token }]) {
    assert.throws(() => f.api.readAgentResultData(f.driver, f.artifacts, f.cut, fake));
    assert.throws(() => f.api.createAgentResultReadData(f.driver, f.artifacts, f.cut, fake));
  }
  assert.throws(() => f.api.readAgentResultData({}, f.artifacts, f.cut, original.token));
  assert.throws(() => f.api.readAgentResultData(f.driver, new ArtifactCatalog(f.cas), f.cut, original.token));
  assert.throws(() => f.api.readAgentResultData(f.driver, f.artifacts, structuredClone(f.cut), original.token));
});

test('a fresh cut reopens actual CAS and cannot inherit an earlier successful history after byte corruption', async t => {
  const f = await fixture(t), one = await f.open(), two = await f.open(structuredClone(f.cut));
  assert.notEqual(await one.data.basis(), await two.data.basis());
  assert.deepEqual(f.calls, ['item', 'progress', 'item', 'progress', 'basis', 'basis']);
  const file = path.join(f.root, f.refs.progress!), before = await readFile(file);
  await chmod(file, 0o600); await writeFile(file, Buffer.alloc(before.length, 0x20)); await chmod(file, 0o400);
  try { await assert.rejects(f.open(structuredClone(f.cut)), /corrupt|digest/u); }
  finally { await chmod(file, 0o600); await writeFile(file, before); await chmod(file, 0o400); }
  const three = await f.open(structuredClone(f.cut)); assert.equal((await three.data.basis()).kind, 'inert-basis');
});

for (const changed of ['run', 'checkpoint', 'items', 'journal', 'launches', 'generations', 'allocations', 'admission', 'principal', 'session'] as const)
  test(`completed family still rejects actual SQLite ${changed} drift before cached reuse`, async t => {
    const f = await fixture(t), value = await f.open(); await value.data.basis();
    const id = changed === 'checkpoint' ? f.cut.run.latestCheckpointId : ['principal', 'session'].includes(changed)
      ? f.cut.run.sessionId : f.cut.run.id;
    const before = f.record<unknown>(changed, id);
    const next = changed === 'session' ? { ...before as object, workspaceIdentityRef: 'different-inert-workspace' }
      : typeof before === 'string' ? 'different-inert-principal' : Array.isArray(before)
      ? [...before, { changed: true }] : { ...before as object, changed: true };
    f.write(changed, id, next);
    await assert.rejects(value.data.basis());
    assert.deepEqual(f.calls, ['item', 'progress', 'basis']);
  });

test('cancelling completed data rejects cache hits with the original reason and starts no additional CAS read', async t => {
  const f = await fixture(t), controller = new AbortController(), reads = f.artifacts.withReadSignal(controller.signal);
  const value = await f.open(f.cut, reads); await value.data.basis(); const reason = new Error('original result preparation cancelled');
  controller.abort(reason);
  await assert.rejects(value.data.basis(), error => error === reason);
  assert.throws(() => f.api.readAgentResultData(f.driver, reads, f.cut, value.token), error => error === reason);
  assert.deepEqual(f.calls, ['item', 'progress', 'basis']);
});

async function failingReadGroup(reads: ArtifactCatalog, refs: readonly string[], original: Error, retirement: Error, entered: ReturnType<typeof gate>, exit: ReturnType<typeof gate>) {
  let joined = false;
  const result = reads.mapReads(refs, async (ref, index) => {
    if (index === 0) { await readCanonicalArtifact(reads, ref); throw original; }
    entered.release(); await exit.promise;
    try { await readCanonicalArtifact(reads, ref); throw retirement; } finally { joined = true; }
  });
  return { result, joined: () => joined };
}

test('failed history joins issued reads and preserves retirement failure before any completed token can be minted', async t => {
  const f = await fixture(t), entered = gate(), exit = gate(), ordinary = new Error('inert read failure');
  const retirement = new ResourceRetirementError('inert original resource join failed', ordinary);
  let group: Awaited<ReturnType<typeof failingReadGroup>> | undefined;
  f.hooks.history = async input => {
    group = await failingReadGroup(input.artifacts, [f.refs.item!, f.refs.progress!], ordinary, retirement, entered, exit);
    return group.result;
  };
  let settled = false; const opening = f.open().finally(() => { settled = true; });
  await entered.promise; await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(settled, false); exit.release();
  await assert.rejects(opening, error => error === retirement); assert.equal(group!.joined(), true);
  delete f.hooks.history;
  assert.equal((await (await f.open(structuredClone(f.cut))).data.basis()).kind, 'inert-basis');
});

test('failed basis joins original readers and never falls back to another success in that family', async t => {
  const f = await fixture(t), value = await f.open(), entered = gate(), exit = gate();
  const retirement = new ResourceRetirementError('inert basis original join failed', new Error('inert read failure'));
  let group: Awaited<ReturnType<typeof failingReadGroup>> | undefined;
  f.hooks.basis = async reads => {
    group = await failingReadGroup(reads, [f.refs.item!, f.refs.progress!], new Error('inert first failure'), retirement, entered, exit);
    await group.result; throw new Error('the failed original read group cannot produce basis data');
  };
  const pending = value.data.basis(); await entered.promise; exit.release();
  await assert.rejects(pending, error => error === retirement); assert.equal(group!.joined(), true);
  delete f.hooks.basis;
  await assert.rejects(value.data.basis(), error => error === retirement);
  assert.equal((await (await f.open(structuredClone(f.cut))).data.basis()).kind, 'inert-basis');
});

test('an active dependency is rejected without self-wait and cannot poison an independent fresh family', async t => {
  const f = await fixture(t), value = await f.open();
  f.hooks.basis = async () => value.data.basis();
  await assert.rejects(value.data.basis(), error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
  delete f.hooks.basis;
  await assert.rejects(value.data.basis(), error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
  assert.equal((await (await f.open(structuredClone(f.cut))).data.basis()).kind, 'inert-basis');
});


test('SQL changes while the original history is in flight prevent minting completed sharing data', async t => {
  const f = await fixture(t), entered = gate(), exit = gate();
  f.hooks.history = async input => {
    const item = await readCanonicalArtifact<Value>(input.artifacts, f.refs.item!);
    entered.release(); await exit.promise;
    const progress = await readCanonicalArtifact<Value>(input.artifacts, f.refs.progress!);
    return { repairAttempts: 0, decodedItems: new Map([['inert-item', item]]), verifierProgressByCandidate: new Map([['inert-candidate', progress]]) };
  };
  const pending = f.open(); await entered.promise;
  f.write('launches', f.cut.run.id, [{ phase: 'retired', original: true, changed: true }]); exit.release();
  await assert.rejects(pending, /SQL changed during validation/u);
  delete f.hooks.history; f.write('launches', f.cut.run.id, [{ phase: 'retired', original: true }]);
  assert.equal((await (await f.open(structuredClone(f.cut))).data.basis()).kind, 'inert-basis');
});

test('a caller cannot change the captured cut object to reuse a token for another revision', async t => {
  const f = await fixture(t), original = await f.open(); await original.data.basis();
  f.cut.run.revision++;
  assert.throws(() => f.api.readAgentRecoveryData(f.driver, f.artifacts, f.cut, original.history.data), /not from this exact completed read/u);
  await assert.rejects(original.data.basis(), /not from this exact completed read/u);
  assert.deepEqual(f.calls, ['item', 'progress', 'basis']);
});


for (const cancelled of [false, true]) test(`closing a ${cancelled ? 'cancelled' : 'completed'} read call discards its exact history and cached result family`, async t => {
  const f = await fixture(t), controller = new AbortController(), reads = f.artifacts.withReadSignal(controller.signal);
  const original = await f.open(f.cut, reads), basis = await original.data.basis();
  assert.equal(await original.data.basis(), basis);
  assert.throws(() => f.api.closeAgentResultReadData({}, reads, f.cut, original.token), /cannot close another result recovery read/u);
  if (cancelled) controller.abort(new Error('original completed read call cancelled'));
  // This is only data-scope invalidation. The real CAS reads above have
  // already joined; close neither closes resources nor proves retirement.
  f.api.closeAgentResultReadData(f.driver, reads, f.cut, original.token);
  assert.throws(() => f.api.readAgentResultData(f.driver, reads, f.cut, original.token), /not from this exact completed recovery read/u);
  assert.throws(() => f.api.readAgentRecoveryData(f.driver, reads, f.cut, original.history.data));
  assert.throws(() => f.api.createAgentResultReadData(f.driver, reads, f.cut, original.history.data));
  assert.throws(() => f.api.closeAgentRecoveryData(f.driver, reads, f.cut, original.history.data), /cannot close another Agent recovery read/u,
    'closing the result call also invalidates the exact original history token, even after cancellation');
  await assert.rejects(original.data.basis());
  assert.deepEqual(f.calls, ['item', 'progress', 'basis']);
  const next = await f.open(structuredClone(f.cut));
  assert.notEqual(await next.data.basis(), basis);
  assert.deepEqual(f.calls, ['item', 'progress', 'basis', 'item', 'progress', 'basis']);
});
