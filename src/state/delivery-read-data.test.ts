// Execute the actual internal DAG over inert JSON, ordinary SQLite records and
// genuine CAS reads. None of these records is a Run/StateOwner/native proof;
// successful installed Delivery remains a separate Linux acceptance obligation.
import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test, type TestContext } from 'node:test';
import { Script } from 'node:vm';
import ts from 'typescript';
import { canonicalSha256 } from '../kernel/canonical.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, ResourceRetirementError, stateOperation } from './errors.js';
import { decodeVerificationClosure } from './result-artifacts.js';

type Projection = { id: string; sessionId?: string; revision: number };
type DataCut = { run: Projection; items: Array<{ itemId: string; payloadRef: string }> };
type Admission = { run: Projection; source: { run: Projection; session: { id: string; workspaceIdentityRef: string } };
  target: { workspaceIdentityRef: string } };
type Value = Record<string, unknown>;
type Nodes = {
  admission(): Promise<Admission>; merges(): Promise<Map<string, Value>>; basis(): Promise<Value>;
  verification(ref: string): Promise<Value>; authorization(): Promise<Value | undefined>;
  histories(): Promise<Map<string, Value | undefined>>; prefix(): Promise<Value>; terminalProjection(ref: string): Promise<Value>;
  stop(ref?: string): Promise<Value>; unclaimedStopHistory(): Promise<ReadonlySet<number>>;
};
type Factory = (driver: unknown, reads: ArtifactCatalog, cut: DataCut) => Nodes;

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

async function factory(dependencies: Record<string, unknown>): Promise<Factory> {
  const body = await readFile(new URL('./delivery-read-data.ts', import.meta.url), 'utf8');
  const source = ts.createSourceFile('delivery-read-data.ts', body, ts.ScriptTarget.Latest, true);
  const declaration = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'createDeliveryReadData');
  assert(declaration, 'execute the actual private data factory, never an authority-bearing caller');
  const names = Object.keys(dependencies);
  const executable = ts.transpileModule(declaration.getText(source).replace(/^export\s+/u, ''),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const create = new Script(`(function(${names.join(',')}) { ${executable}; return createDeliveryReadData; })`,
    { filename: 'actual-delivery-read-data-expression.js' }).runInThisContext() as (...values: unknown[]) => Factory;
  return create(...names.map(name => dependencies[name]));
}

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-delivery-read-data-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const database = new DatabaseSync(':memory:'); t.after(() => database.close());
  database.exec('CREATE TABLE inert_records(kind TEXT NOT NULL,id TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(kind,id)) STRICT');
  const write = (kind: string, id: string, value: unknown) => database.prepare(
    'INSERT OR REPLACE INTO inert_records VALUES(?,?,?)').run(kind, id, JSON.stringify(value));
  const record = <T>(kind: string, id: string): T => {
    const row = database.prepare('SELECT value FROM inert_records WHERE kind=? AND id=?').get(kind, id);
    assert(row && typeof row.value === 'string', 'only an actual ordinary fixture record can be selected');
    return JSON.parse(row.value) as T;
  };
  const run: Projection = { id: 'inert-target', sessionId: 'inert-session', revision: 1 };
  const sourceRun: Projection = { id: 'inert-source', revision: 2 };
  write('projection', run.id, run); write('projection', sourceRun.id, sourceRun);
  write('session', 'inert-session', { workspaceIdentityRef: 'inert-workspace' });
  write('principal', 'inert-session', 'inert-principal');
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
  const admission: Admission = { run, source: { run: sourceRun, session: { id: 'inert-session', workspaceIdentityRef: 'inert-workspace' } },
    target: { workspaceIdentityRef: 'inert-workspace' } };
  const refs: Record<string, string> = {};
  for (const [kind, value] of Object.entries({ admission, merge: { kind: 'merge' }, basis: { kind: 'basis' },
    verification: { kind: 'verification' }, alternate: { kind: 'verification', alternate: true },
    authorization: { kind: 'authorization' }, histories: { kind: 'histories' }, prefix: { kind: 'prefix' },
    terminalProjection: { kind: 'terminal-projection-data-only' }, stop: { kind: 'stop-data-only' },
    unclaimedStopHistory: { kind: 'unclaimed-stop-data-only' } })) {
    refs[kind] = (await artifacts.publishCanonical(value, 'inert-delivery-dag-data')).ref;
  }
  const calls: string[] = [], retained: Record<string, unknown> = {};
  const read = async (reads: ArtifactCatalog, kind: string, ref = refs[kind]!) => {
    calls.push(kind); return readCanonicalArtifact<Value>(reads, ref);
  };
  const cut: DataCut = { run, items: [] };
  const assertCut = async (_driver: unknown, reads: ArtifactCatalog, actual: DataCut) => {
    reads.assertReadActive();
    assert.equal(canonicalSha256(record('projection', actual.run.id)), canonicalSha256(actual.run), 'actual ordinary SQL cut changed');
  };
  const dependencies: Record<string, unknown> = {
    canonicalSha256, KernelStorageError, ResourceRetirementError, readCanonicalArtifact,
    readSessionPrincipalId: (_driver: unknown, id: string) => record('principal', id),
    readRun: (_driver: unknown, id: string) => record('projection', id),
    readSession: (_driver: unknown, id: string) => record('session', id),
    readCheckpoint: () => { throw new Error('the inert fixture has no Checkpoint records'); },
    assertPublicationReadCut: assertCut,
    readDeliveryRunAdmission: async (_driver: unknown, reads: ArtifactCatalog) => {
      const value = await read(reads, 'admission'); retained.admission = value; return value;
    },
    validateDeliveryRecoveryData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, value: Admission) => {
      assert.equal(value, retained.admission); const result = new Map([['merge', await read(reads, 'merge')]]);
      retained.merges = result; return result;
    },
    readDeliveryResultData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, value: Admission, merges: unknown) => {
      assert.equal(value, retained.admission); assert.equal(merges, retained.merges);
      const result = await read(reads, 'basis'); retained.basis = result; return result;
    },
    readDeliveryVerificationBasis: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, ref: string, basis: unknown) => {
      assert.equal(basis, retained.basis); const result = await read(reads, 'verification', ref);
      assert.equal(result.kind, 'verification', 'each verification use still decodes its own required data shape');
      return result;
    },
    readDeliveryAuthorizationData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, verify: Nodes['verification']) => {
      const verified = await verify(refs.verification!); return { ...await read(reads, 'authorization'), verified };
    },
    validatePublicationInvocationHistoryData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, authorize: Nodes['authorization']) => {
      const authorization = await authorize(); await read(reads, 'histories'); return new Map([['original', authorization]]);
    },
    readPublicationPrefixData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, data: Nodes) => {
      const value = await data.admission(), authorization = await data.authorization(), histories = await data.histories();
      return { ...await read(reads, 'prefix'), admission: value, authorization, histories };
    },
    readDeliveryTerminalProjectionData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, ref: string, data: Nodes) => {
      const prefix = await data.prefix(); return { ...await read(reads, 'terminalProjection', ref), prefix };
    },
    readAgentStopInDeliveryEpoch: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, data: Nodes) => {
      await data.authorization(); return { ...await read(reads, 'stop'), selection: 'current' };
    },
    readRetainedAgentStopInDeliveryEpoch: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, ref: string, data: Nodes) => {
      await data.authorization(); return { ...await read(reads, 'stop', ref), selection: 'retained' };
    },
    readUnclaimedPublicationStopHistoryData: async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, prefix: Nodes['prefix']) => {
      await prefix(); await read(reads, 'unclaimedStopHistory'); return new Set([1]);
    }
  };
  const driver = { prepare(sql: string) {
    assert.equal(sql, 'SELECT id FROM checkpoints WHERE run_id=? ORDER BY rowid');
    return { all(id: string) { assert.equal(id, run.id); return []; } };
  } };
  return { directory, root, database, write, cas, artifacts, refs, cut, admission, calls, dependencies, driver,
    create: async () => (await factory(dependencies))(driver, artifacts, cut) };
}

test('one actual data DAG shares completed nodes and original values without accepting a Delivery or owner', async t => {
  const held = await fixture(t), data = await held.create();
  const prefix = await data.prefix(), verification = await data.verification(held.refs.verification!);
  assert.equal(await data.admission(), prefix.admission);
  assert.equal(await data.authorization(), prefix.authorization);
  assert.equal(await data.histories(), prefix.histories);
  assert.equal((prefix.authorization as Value).verified, verification);
  assert.equal(await data.prefix(), prefix);
  await data.merges(); await data.basis();
  assert.deepEqual(held.calls, ['admission', 'merge', 'basis', 'verification', 'authorization', 'histories', 'prefix']);
});

test('a new data epoch reopens the genuine CAS bytes rather than inheriting completed nodes', async t => {
  const held = await fixture(t), first = await held.create(), second = await held.create();
  assert.notEqual(await first.prefix(), await second.prefix());
  assert.deepEqual(held.calls, Array.from({ length: 2 }, () =>
    ['admission', 'merge', 'basis', 'verification', 'authorization', 'histories', 'prefix']).flat());
  const original = held.cas.read.bind(held.cas), bytes = await original(held.refs.admission!);
  const file = path.join(held.root, held.refs.admission!);
  try {
    await fs.chmod(file, 0o600); await fs.writeFile(file, Buffer.alloc(bytes.length, 0x20)); await fs.chmod(file, 0o400);
    const third = await held.create();
    await assert.rejects(third.admission(), /is corrupt/u,
      'a separately created epoch must not accept the earlier decoded admission after its actual bytes change');
  } finally {
    await fs.chmod(file, 0o600); await fs.writeFile(file, bytes); await fs.chmod(file, 0o400);
  }
});

test('two concurrently opened data epochs do not share active nodes or decoded admission objects', async t => {
  const held = await fixture(t), first = await held.create(), second = await held.create();
  const [one, two] = await Promise.all([first.admission(), second.admission()]);
  assert.notEqual(one, two); assert.deepEqual(one, two);
  assert.deepEqual(held.calls, ['admission', 'admission']);
});

for (const drift of ['target', 'source', 'principal', 'workspace'] as const) {
  test(`completed admission data still rejects original ordinary-SQL ${drift} drift`, async t => {
    const held = await fixture(t), data = await held.create(); await data.admission();
    if (drift === 'target') held.write('projection', held.cut.run.id, { ...held.cut.run, revision: 2 });
    if (drift === 'source') held.write('projection', held.admission.source.run.id, { ...held.admission.source.run, revision: 3 });
    if (drift === 'principal') held.write('principal', 'inert-session', 'another-inert-principal');
    if (drift === 'workspace') held.write('session', 'inert-session', { workspaceIdentityRef: 'another-inert-workspace' });
    await assert.rejects(data.admission(), error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
    assert.deepEqual(held.calls, ['admission'], 'completed JSON is shared but its original current-cut checks are not cached');
  });
}

test('verification reuse is keyed by the exact closure ref and not by a previous successful use', async t => {
  const held = await fixture(t), data = await held.create();
  const original = await data.verification(held.refs.verification!), alternate = await data.verification(held.refs.alternate!);
  assert.notEqual(original, alternate); assert.equal(alternate.alternate, true);
  assert.equal(await data.verification(held.refs.verification!), original);
  assert.deepEqual(held.calls, ['admission', 'merge', 'basis', 'verification', 'verification']);
});

test('the original verification decoder rejects a different CAS use again at the next fresh epoch', async t => {
  const held = await fixture(t), source = await readFile(new URL('./run-result-recovery.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('run-result-recovery.ts', source, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'readDeliveryVerificationBasis');
  assert(declaration?.body, 'the actual purpose-specific verification decoder must remain in the shared node');
  const first = declaration.body.statements[0]!;
  assert(ts.isVariableStatement(first), 'execute the actual first verification data read, not a fabricated successful graph');
  const expression = first.declarationList.declarations[0]?.initializer;
  assert(expression && ts.isCallExpression(expression) && expression.expression.getText(parsed) === 'decodeVerificationClosure');
  const executable = ts.transpileModule(`(async function(artifacts,closureRef,decodeVerificationClosure,readCanonicalArtifact) {
    return ${expression.getText(parsed)};
  })`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const decode = new Script(executable).runInThisContext() as (artifacts: ArtifactCatalog, ref: string,
    decoder: typeof decodeVerificationClosure, read: typeof readCanonicalArtifact) => Promise<unknown>;
  let issued = 0;
  held.dependencies.readDeliveryVerificationBasis = async (_driver: unknown, reads: ArtifactCatalog, _cut: unknown, ref: string) => {
    issued++; return decode(reads, ref, decodeVerificationClosure, readCanonicalArtifact);
  };
  const data = await held.create();
  assert.deepEqual(await readCanonicalArtifact(held.artifacts, held.refs.authorization!), { kind: 'authorization' });
  const mismatch = (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH';
  await assert.rejects(data.verification(held.refs.authorization!), mismatch);
  const next = await held.create();
  await assert.rejects(next.verification(held.refs.authorization!), mismatch);
  assert.equal(issued, 2, 'a previous failed traversal cannot supply another fresh entry with verification or a cached refusal');
});

test('an internal data dependency cycle rejects before self-wait and does not poison another fresh epoch', async t => {
  const held = await fixture(t); let data: Nodes;
  held.dependencies.readDeliveryAuthorizationData = async () => data.authorization();
  data = await held.create();
  await assert.rejects(data.authorization(), error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
  const independent = await fixture(t);
  assert.equal((await (await independent.create()).prefix()).kind, 'prefix');
});

test('undefined authorization is a completed data result rather than an invented allow grant', async t => {
  const held = await fixture(t); let calls = 0;
  held.dependencies.readDeliveryAuthorizationData = async () => { calls++; return undefined; };
  const data = await held.create();
  assert.equal(await data.authorization(), undefined); assert.equal(await data.authorization(), undefined);
  const prefix = await data.prefix();
  assert.equal(prefix.authorization, undefined); assert.equal(calls, 1);
  assert.equal((prefix.histories as Map<string, unknown>).get('original'), undefined);
});

test('terminal projection keeps its independent reads while reusing only this epoch retained prefix', async t => {
  const held = await fixture(t), data = await held.create();
  const first = await data.terminalProjection(held.refs.terminalProjection!), second = await data.terminalProjection(held.refs.terminalProjection!);
  assert.notEqual(first, second); assert.equal(first.prefix, second.prefix);
  assert.deepEqual(held.calls, ['admission', 'merge', 'basis', 'verification', 'authorization', 'histories', 'prefix',
    'terminalProjection', 'terminalProjection']);
});

test('cancelling a completed data epoch still rejects every later access with the original read reason', async t => {
  const held = await fixture(t), controller = new AbortController(), reads = held.artifacts.withReadSignal(controller.signal);
  const data = (await factory(held.dependencies))(held.driver, reads, held.cut);
  await data.prefix(); const originalCalls = [...held.calls], reason = new Error('original completed traversal cancelled');
  controller.abort(reason);
  for (const read of [() => data.admission(), () => data.merges(), () => data.basis(), () => data.verification(held.refs.verification!),
    () => data.authorization(), () => data.histories(), () => data.prefix(), () => data.terminalProjection(held.refs.terminalProjection!),
    () => data.stop(), () => data.stop(held.refs.stop!), () => data.unclaimedStopHistory()]) {
    await assert.rejects(read(), error => error === reason);
  }
  assert.deepEqual(held.calls, originalCalls, 'cancelled completed data cannot start another read or become a usable prefix');
});

test('Stop and unclaimed-stop reads keep their own observations without recursing through a full recovery entry', async t => {
  const held = await fixture(t), data = await held.create();
  const current = await data.stop(), retained = await data.stop(held.refs.stop!);
  assert.equal(current.selection, 'current'); assert.equal(retained.selection, 'retained');
  assert.notEqual(await data.stop(), current, 'the same epoch cannot cache a later Stop observation');
  const first = await data.unclaimedStopHistory(), second = await data.unclaimedStopHistory();
  assert.deepEqual([...first], [1]); assert.deepEqual([...second], [1]); assert.notEqual(first, second);
  assert.deepEqual(held.calls, ['admission', 'merge', 'basis', 'verification', 'authorization', 'stop', 'stop', 'stop',
    'histories', 'prefix', 'unclaimedStopHistory', 'unclaimedStopHistory']);
});

for (const fault of ['cancel', 'retirement'] as const) {
  test(`a failed epoch joins its genuine CAS descriptors before exposing ${fault}`, async t => {
    const held = await fixture(t), controller = new AbortController(), reads = held.artifacts.withReadSignal(controller.signal);
    const entered = gate(), release = gate(), firstJoined = gate();
    const reason = new Error('original inert read cancelled'), ordinary = new Error('original inert read failed');
    const closeFailure = new Error('actual closed descriptor reported failure');
    const open = fs.open.bind(fs), rawRead = held.cas.read.bind(held.cas), active = new Set<object>(), raw: Promise<unknown>[] = [];
    let opened = 0, closed = 0, settled = false, actualRetirement: ResourceRetirementError | undefined;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args); active.add(handle); opened++;
      const close = handle.close.bind(handle), read = handle.read.bind(handle);
      if (args[0] === path.join(held.root, held.refs.merge!) && fault === 'retirement') {
        t.mock.method(handle, 'read', async (...values: Parameters<typeof handle.read>) => { await read(...values); throw ordinary; });
      }
      t.mock.method(handle, 'close', async () => {
        await close(); assert(active.delete(handle), 'a real handed-out descriptor is joined exactly once'); closed++;
        if (args[0] === path.join(held.root, held.refs.basis!)) {
          entered.release(); await release.promise;
          if (fault === 'retirement') throw closeFailure;
        }
      });
      return handle;
    });
    t.mock.method(held.cas, 'read', (...args: Parameters<typeof held.cas.read>) => {
      const pending = rawRead(...args); raw.push(pending);
      return pending.catch(error => {
        if (error instanceof ResourceRetirementError && error.cause === closeFailure) actualRetirement = error;
        throw error;
      }).finally(() => { if (args[0] === held.refs.merge) firstJoined.release(); });
    });
    held.dependencies.readDeliveryRunAdmission = async (_driver: unknown, catalog: ArtifactCatalog) => {
      await catalog.mapReads([held.refs.merge!, held.refs.basis!], ref => readCanonicalArtifact(catalog, ref));
      return held.admission;
    };
    const data = (await factory(held.dependencies))(held.driver, reads, held.cut), pending = data.admission();
    void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.all([entered.promise, firstJoined.promise]);
      if (fault === 'cancel') controller.abort(reason);
      await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(raw.length, 2); assert(active.size > 0, 'the original pending CAS root is still physically owned');
      assert.equal(settled, false, 'the epoch cannot return while the issued original read still owns resources');
      release.release();
      await assert.rejects(pending, error => fault === 'cancel' ? error === reason :
        error === actualRetirement && error instanceof ResourceRetirementError && error.cause === closeFailure);
      assert.equal(active.size, 0); assert.equal(opened, closed);
      assert.deepEqual(held.calls, [], 'no downstream data node becomes a successful prefix after the failed admission');
    } finally {
      release.release(); await Promise.allSettled([pending, ...raw]);
      assert.equal(active.size, 0); assert.equal(opened, closed);
    }
  });
}

test('the original source-walk rule permits separate source branches but refuses an active ancestor cycle', async t => {
  const held = await fixture(t), source = await readFile(new URL('./delivery-source-authority.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('delivery-source-authority.ts', source, ts.ScriptTarget.Latest, true);
  const statement = parsed.statements.find((node): node is ts.VariableStatement => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(value => value.name.getText(parsed) === 'readRetainedVerifiedDeliverySource'));
  const initializer = statement?.declarationList.declarations.find(value => value.name.getText(parsed) === 'readRetainedVerifiedDeliverySource')?.initializer;
  assert(initializer, 'execute the existing source ancestor rule, not a replacement memo or fabricated verified source');
  type Input = { principalId: string; sourceRunId: string; expectedRunResultRef: string };
  type ReadSource = (driver: unknown, artifacts: ArtifactCatalog, input: Input) => Promise<unknown>;
  const edges = new Map<string, string[]>([['a', ['b', 'b']], ['b', ['c']]]), visited: string[] = [];
  let invoke: ReadSource;
  const graph: ReadSource = async (driver, artifacts, input) => {
    visited.push(input.sourceRunId);
    for (const child of edges.get(input.sourceRunId) ?? []) await invoke(driver, artifacts, { ...input, sourceRunId: child });
    return readCanonicalArtifact(artifacts, held.refs.prefix!);
  };
  const executable = ts.transpileModule(`(function(stateOperation,KernelStorageError,sourceWalk,readSourceGraph) {
    return ${initializer.getText(parsed)};
  })`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const create = new Script(executable).runInThisContext() as (wrap: typeof stateOperation, error: typeof KernelStorageError,
    walk: AsyncLocalStorage<ReadonlySet<string>>, graph: ReadSource) => ReadSource;
  invoke = create(stateOperation, KernelStorageError, new AsyncLocalStorage<ReadonlySet<string>>(), graph);
  const input = { principalId: 'inert-principal', sourceRunId: 'a', expectedRunResultRef: held.refs.prefix! };
  await invoke(held.driver, held.artifacts, input);
  assert.deepEqual(visited, ['a', 'b', 'c', 'b', 'c']);
  edges.set('b', ['a']); visited.length = 0;
  await assert.rejects(invoke(held.driver, held.artifacts, input), error =>
    error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
  assert.deepEqual(visited, ['a', 'b'], 'a cycle is refused before entering the repeated original source');
  edges.clear(); visited.length = 0; await invoke(held.driver, held.artifacts, input);
  assert.deepEqual(visited, ['a'], 'an earlier epoch cannot leave a global source-seen cache');
});

test('every actual received, handoff, seal and settlement read call opens independent data epochs', async t => {
  const held = await fixture(t), expected = new Map([
    ['run-execution.ts', ['finishReceivedPublication', 'executeCurrentPublication']],
    ['publication-finalization.ts', ['handoffOwnedPublicationResult', 'prepareOwnedPublicationReceivedResult', 'prepareOwnedPublicationGenerationSeal']],
    ['publication-settlement.ts', ['select', 'selectReceived', 'selectPreparation']]
  ]);
  for (const [file, owners] of expected) {
    const body = await readFile(new URL(`./${file}`, import.meta.url), 'utf8');
    const parsed = ts.createSourceFile(file, body, ts.ScriptTarget.Latest, true), calls = new Map<string, ts.CallExpression>();
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'readDeliveryPublicationClosure') {
        let owner: ts.Node | undefined = node.parent;
        while (owner && !ts.isFunctionDeclaration(owner) && !ts.isPropertyAssignment(owner)) owner = owner.parent;
        assert(owner && (ts.isFunctionDeclaration(owner) || ts.isPropertyAssignment(owner)) && owner.name,
          `${file}: an actual named acceptance read must own the fresh call`);
        const name = owner.name.getText(parsed);
        assert(!calls.has(name), `${file}: one acceptance must not manufacture a second partial projection`);
        calls.set(name, node);
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    assert.deepEqual([...calls.keys()], owners, `${file}: preserve all original complete acceptance points, including the seal and handoff loop`);
    for (const [owner, call] of calls) {
      const executable = ts.transpileModule(`(async function(readDeliveryPublicationClosure,driver,artifacts,reads,runId,binding,resources,completion) {
        return ${call.getText(parsed)};
      })`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
      type Paired = (driver: unknown, reads: ArtifactCatalog, runId: string) => Promise<{ cut: DataCut; prefix: Value }>;
      type Invoke = (read: Paired, driver: unknown, artifacts: ArtifactCatalog, reads: ArtifactCatalog, runId: string,
        binding: unknown, resources: unknown, completion: unknown) => ReturnType<Paired>;
      const invoke = new Script(executable).runInThisContext() as Invoke;
      let entries = 0;
      const paired: Paired = async (driver, reads, runId) => {
        assert.equal(driver, held.driver); assert.equal(reads, held.artifacts); assert.equal(runId, held.cut.run.id); entries++;
        const data = (await factory(held.dependencies))(driver, reads, held.cut);
        return { cut: held.cut, prefix: await data.prefix() };
      };
      const binding = { driver: held.driver, artifacts: held.artifacts, reads: held.artifacts,
        input: { runId: held.cut.run.id }, item: { runId: held.cut.run.id } };
      const args = [paired, held.driver, held.artifacts, held.artifacts, held.cut.run.id, binding,
        { runId: held.cut.run.id }, { run: { id: held.cut.run.id } }] as const;
      const first = await invoke(...args), second = await invoke(...args);
      assert.equal(entries, 2, `${file}/${owner}: subsequent acceptance cannot borrow the previous fresh entry`);
      assert.notEqual(first.prefix, second.prefix);
    }
    if (file === 'publication-settlement.ts') {
      let selected: ts.CallExpression | undefined;
      const find = (node: ts.Node) => {
        if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'selectReceived') {
          let ancestor: ts.Node | undefined = node.parent;
          while (ancestor && !ts.isForStatement(ancestor)) ancestor = ancestor.parent;
          if (ancestor && ts.isForStatement(ancestor)) {
            assert(ts.isTryStatement(ancestor.statement), 'the original retry owns the fresh selection inside its guarded try');
            const clause = ancestor.statement.catchClause;
            assert(clause, 'the original Session-only retry must remain guarded');
            const refusal = clause.block.statements[0];
            assert(refusal && ts.isIfStatement(refusal) && ts.isThrowStatement(refusal.thenStatement));
            assert.equal(refusal.expression.getText(parsed), 'retry >= 7 || !isOwnedPublicationSessionConflict(driver, owner, binding.receivedResult, error)',
              'only the original exact Session conflict may repeat a fresh selection');
            selected = node;
          }
        }
        ts.forEachChild(node, find);
      };
      find(parsed); assert(selected, 'every actual received settle attempt must select again inside the original Session retry loop');
    }
  }
});
