// Actual CAS resources and inert production read expressions only. No Run,
// StateOwner, native proof or installed Linux qualification is constructed.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { Script } from 'node:vm';
import ts from 'typescript';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ResourceRetirementError } from './errors.js';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

async function fixture(t: TestContext, count = 8) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-artifact-read-pool-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas), refs: string[] = [];
  for (let index = 0; index < count; index++) refs.push((await artifacts.publishCanonical({ inertIndex: index }, 'pool-data-only')).ref);
  return { root, cas, artifacts, refs };
}

async function stoppedItemReader() {
  const source = await readFile(new URL('./verifier-stop-history.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-stop-history.ts', source, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find((node): node is ts.VariableStatement => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(value => value.name.getText(parsed) === 'readItems'));
  assert(declaration, 'execute exactly the production inert item-read expression, not its authority-bearing callers');
  const context = { readCanonicalArtifact, invoke: undefined as unknown as (artifacts: ArtifactCatalog,
    cut: { items: Array<{ payloadRef: string }> }) => Promise<unknown> };
  new Script(ts.transpileModule(`${declaration.getText(parsed)}; globalThis.invoke = readItems;`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText).runInNewContext(context);
  return context.invoke;
}

test('a production item read joins every issued real CAS close and preserves a later retirement failure before its owner can finish', async t => {
  const invoke = await stoppedItemReader(), { root, cas, artifacts, refs } = await fixture(t);
  const entered = gate(), release = gate(), ordinaryJoined = gate();
  const ordinary = new Error('an actual file read reported failure'), retirement = new Error('an actual closed file reported retirement failure');
  const open = fs.open.bind(fs), read = cas.read.bind(cas), active = new Set<object>(), raw: Promise<unknown>[] = [];
  let opened = 0, closed = 0, settled = false;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args); active.add(handle); opened++;
    const close = handle.close.bind(handle), actualRead = handle.read.bind(handle);
    if (args[0] === path.join(root, refs[0]!)) t.mock.method(handle, 'read', async (...values: Parameters<typeof handle.read>) => {
      await actualRead(...values); throw ordinary;
    });
    t.mock.method(handle, 'close', async () => {
      await close(); assert(active.delete(handle)); closed++;
      if (args[0] === path.join(root, refs[1]!)) { entered.release(); await release.promise; throw retirement; }
      if (args[0] === path.join(root, refs[2]!) || args[0] === path.join(root, refs[3]!)) {
        // Keep these real issued sibling returns pending until the original
        // I/O failure has propagated to the production pool. A fast success
        // before that failure is known may legitimately dispatch another row.
        await ordinaryJoined.promise;
        await new Promise<void>(resolve => setImmediate(resolve));
      }
    });
    return handle;
  });
  t.mock.method(cas, 'read', (...args: Parameters<typeof cas.read>) => {
    const pending = read(...args); raw.push(pending);
    return pending.catch(error => { if (args[0] === refs[0]) ordinaryJoined.release(); throw error; });
  });
  const pending = invoke(artifacts, { items: refs.map(payloadRef => ({ payloadRef })) });
  void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await Promise.all([entered.promise, ordinaryJoined.promise]);
    await new Promise<void>(resolve => setImmediate(resolve));
    t.diagnostic(JSON.stringify({ issuedReads: raw.length, realDescriptorsStillOwned: active.size, outerSettled: settled }));
    assert(active.size > 0, 'the gated real file close still owns its original root descriptor');
    assert.equal(settled, false, 'an ordinary read error cannot release an owner while its issued sibling has not joined');
    release.release();
    await assert.rejects(pending, error => error instanceof ResourceRetirementError && error.cause === retirement);
    assert.equal(raw.length, 4, 'a failed first wave never dispatches the queued references');
    assert.equal(active.size, 0); assert.equal(opened, closed);
  } finally {
    release.release(); await Promise.allSettled([pending, ...raw]);
    assert.equal(active.size, 0); assert.equal(opened, closed);
  }
});

test('all six retained readers pass the original lazy callbacks to the bounded catalog group, including the fixed two-source read', async () => {
  const expected = new Map([
    ['run-result-recovery.ts', ['cut.items']], ['verifier-completion.ts', ['selected.items']],
    ['verifier-repair.ts', ['cut.items']], ['verifier-recovery.ts', ['cut.workspaceGenerations']],
    ['final-candidate-recovery.ts', ["input.workspaceGenerations.filter(generation => generation.phase === 'sealed')"]],
    ['verifier-stop-history.ts', ['cut.items', '[before, after]']]
  ]);
  for (const [file, lists] of expected) {
    const body = await readFile(new URL(`./${file}`, import.meta.url), 'utf8');
    const parsed = ts.createSourceFile(file, body, ts.ScriptTarget.Latest, true), calls: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'artifacts.mapReads') calls.push(node);
      if (ts.isCallExpression(node)) assert.notEqual(node.expression.getText(parsed), 'Promise.all', `${file}: no fail-fast CAS group remains`);
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    assert.deepEqual(calls.map(call => call.arguments[0]!.getText(parsed)), lists, file);
    for (const call of calls) {
      assert.equal(call.arguments.length, 2);
      assert(ts.isArrowFunction(call.arguments[1]!), `${file}: pass a callback, never already-started promises`);
    }
  }
});

test('lazy real reads occupy at most four callback slots and retain input order across out-of-order completion', async t => {
  const { artifacts, refs } = await fixture(t, 12), entered = refs.map(gate), release = refs.map(gate);
  const open = fs.open.bind(fs), handles = new Set<object>(), issued: number[] = [], completed: number[] = [];
  let active = 0, peak = 0, fdPeak = 0, opened = 0, closed = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args); handles.add(handle); opened++; fdPeak = Math.max(fdPeak, handles.size);
    const close = handle.close.bind(handle);
    t.mock.method(handle, 'close', async () => { await close(); assert(handles.delete(handle)); closed++; });
    return handle;
  });
  const pending = artifacts.mapReads(refs, async (ref, index) => {
    issued.push(index); active++; peak = Math.max(peak, active);
    try {
      const item = await artifacts.readCanonical<{ inertIndex: number }>(ref);
      entered[index]!.release(); await release[index]!.promise; completed.push(index); return item.inertIndex;
    } finally { active--; }
  });
  try {
    await Promise.all(entered.slice(0, 4).map(value => value.promise));
    assert.deepEqual(issued, [0, 1, 2, 3]); assert.equal(active, 4);
    for (const [finished, started] of [[2, 4], [0, 5], [3, 6], [1, 7]]) {
      release[finished!]!.release(); await entered[started!]!.promise;
      assert.equal(active, 4); assert.equal(issued.at(-1), started);
    }
    for (const value of release) value.release();
    assert.deepEqual(await pending, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert.deepEqual(completed.slice(0, 4), [2, 0, 3, 1]);
    assert.equal(peak, 4);
    assert(fdPeak > 0 && fdPeak <= 8, 'only this leaf-read fixture owns at most two actual CAS handles per callback, not a global graph bound');
    assert.equal(active, 0); assert.equal(handles.size, 0); assert.equal(opened, closed);
  } finally {
    for (const value of release) value.release(); await Promise.allSettled([pending]);
    assert.equal(active, 0); assert.equal(handles.size, 0); assert.equal(opened, closed);
  }
});

test('cancelling a read view stops queued real reads but joins every already-issued return gate and preserves the original reason', async t => {
  const { artifacts, refs } = await fixture(t), owner = new AbortController(), reason = new Error('original read lifetime cancelled');
  const view = artifacts.withReadSignal(owner.signal), entered = refs.map(gate), release = refs.map(gate), issued: number[] = [];
  let settled = false, active = 0;
  const pending = view.mapReads(refs, async (ref, index) => {
    issued.push(index); active++;
    try {
      const value = await view.readCanonical(ref); entered[index]!.release(); await release[index]!.promise; return value;
    } finally { active--; }
  });
  void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await Promise.all(entered.slice(0, 4).map(value => value.promise));
    owner.abort(reason); release[0]!.release();
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.deepEqual(issued, [0, 1, 2, 3]); assert.equal(settled, false); assert.equal(active, 3);
    for (const value of release) value.release();
    await assert.rejects(pending, error => error === reason);
    assert.equal(active, 0); assert.deepEqual(issued, [0, 1, 2, 3]);
  } finally { for (const value of release) value.release(); await Promise.allSettled([pending]); assert.equal(active, 0); }
});

test('pre-cancelled empty and nonempty groups never dispatch, and an empty group still checks cancellation after its join', async t => {
  const { artifacts } = await fixture(t, 0), reason = new Error('original cancelled read view');
  for (const values of [[], [1, 2, 3, 4, 5]]) {
    const owner = new AbortController(); owner.abort(reason);
    let called = false;
    await assert.rejects(artifacts.withReadSignal(owner.signal).mapReads(values, () => { called = true; }), error => error === reason);
    assert.equal(called, false);
  }
  const owner = new AbortController();
  const empty = artifacts.withReadSignal(owner.signal).mapReads([], () => { throw new Error('empty groups cannot dispatch'); });
  owner.abort(reason); await assert.rejects(empty, error => error === reason);
});

test('a synchronous callback failure is preserved without dispatching another slot, including null and undefined rejection values', async t => {
  const { artifacts } = await fixture(t, 0);
  for (const original of [new Error('original synchronous failure'), new ResourceRetirementError('original synchronous retirement', undefined), null, undefined]) {
    let called = 0;
    const pending = artifacts.mapReads([0, 1, 2, 3, 4], () => { called++; throw original; });
    await assert.rejects(pending, error => error === original);
    assert.equal(called, 1);
  }
});

test('multiple callback failures join all issued slots and preserve a selected original retirement error over cancellation', async t => {
  // Pure error-selection data. The actual-close case above separately proves
  // real CAS retirement ownership; these errors do not create native proof.
  const { artifacts } = await fixture(t, 0), owner = new AbortController(), release = [gate(), gate(), gate(), gate()];
  const reason = new Error('cancelled original view'), first = new Error('first ordinary callback failure');
  const retirements = [new ResourceRetirementError('first retirement error object', first),
    new ResourceRetirementError('second retirement error object', first)];
  const failures = [first, reason, ...retirements], issued: number[] = [], joined: number[] = [];
  const view = artifacts.withReadSignal(owner.signal);
  let settled = false;
  const pending = view.mapReads([0, 1, 2, 3, 4, 5], async index => {
    issued.push(index);
    try { await release[index]!.promise; throw failures[index]; } finally { joined.push(index); }
  });
  void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    release[0]!.release(); await new Promise<void>(resolve => setImmediate(resolve));
    owner.abort(reason); release[3]!.release(); await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(settled, false); assert.deepEqual(issued, [0, 1, 2, 3]);
    release[1]!.release(); release[2]!.release();
    await assert.rejects(pending, error => retirements.some(original => error === original));
    assert.deepEqual(joined.sort(), [0, 1, 2, 3]); assert.deepEqual(issued, [0, 1, 2, 3]);
  } finally { for (const value of release) value.release(); await Promise.allSettled([pending]); }
});
