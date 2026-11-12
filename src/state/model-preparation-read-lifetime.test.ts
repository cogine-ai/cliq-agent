// Execute only the production effect-free preparation expressions with inert
// data dependencies and real CAS resources. No native token, Run, StateOwner,
// transport or accepted credential authority is constructed by these tests.
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
import { KernelStorageError, ResourceRetirementError } from './errors.js';

const gate = () => {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { release, promise };
};
async function parsed(filename: string) {
  return ts.createSourceFile(filename, await readFile(new URL(`./${filename}`, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
}
function methods(source: ts.SourceFile, name: string) {
  const result: ts.MethodDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node) && node.name.getText(source) === name) result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(result.length, 1); return result[0]!;
}
function credentialScope(source: ts.SourceFile) {
  const result: ts.FunctionDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.body && node.name?.text === 'performCredentialScope') result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(result.length, 1); return result[0]!;
}
function expression(code: string, dependencies: Record<string, unknown>) {
  const names = Object.keys(dependencies), output = ts.transpileModule(code, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext }
  }).outputText;
  return new Script(`(function(${names.join(',')}) { ${output} })`).runInThisContext()(...Object.values(dependencies));
}
async function brokerPreparation(dependencies: Record<string, unknown>) {
  const source = await parsed('store.ts'), method = methods(source, 'dispatchInstalledModelOwned');
  const end = method.body!.statements.findIndex(node => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(value => value.name.getText(source) === 'trustStoreBytes'));
  assert(end >= 0, 'exercise the original complete pre-transport read sequence');
  return expression(`return async function(execution, agent, attempt, preparationSignal) {
    ${method.body!.statements.slice(0, end + 1).map(node => node.getText(source)).join('\n')}
    return { initial, frozen, trustStoreBytes };
  }`, { KernelStorageError, ...dependencies }) as (this: unknown, execution: unknown, agent: unknown,
    attempt: unknown, signal: AbortSignal) => Promise<Record<string, unknown>>;
}
async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-model-preclaim-read-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root)), refs: string[] = [];
  for (let index = 0; index < 6; index++) refs.push((await artifacts.publishCanonical({ kind: 'inert-binding-data', index }, 'inert-data')).ref);
  const trust = await artifacts.publishBytes(Buffer.from('inert bytes, not a trust store'), 'application/octet-stream', 'inert-data');
  const initial = { assembly: { provider: { name: 'openai-compatible', credentialGrantRefs: refs } },
    authority: { target: { format: 'cliq-endpoint-registration-v1', tls: { trustStoreRef: trust.ref } } } };
  const claim = await artifacts.publishCanonical(initial, 'inert-claim-reader-data'), signals: Array<AbortSignal | undefined> = [];
  const invoke = await brokerPreparation({
    loadInstalledModelBroker: async (_selected: unknown, signal?: AbortSignal) => {
      signals.push(signal); signal?.throwIfAborted(); return Object.freeze({ kind: 'inert-broker-data' });
    },
    readModelClaimCut: async (_driver: unknown, reads: ArtifactCatalog) => reads.readCanonical(claim.ref),
    decodeEndpointCredentialGrantBinding: (value: unknown) => value
  });
  const stop = new AbortController(), selected = Object.freeze({ kind: 'inert-selection-label' });
  const context = { installedRuntime: selected, runtimeAuthority: { kind: 'inert-root-label' }, installedAnchor: { kind: 'inert-anchor-label' },
    artifacts, driver: {}, installedRunPhases: new Map() };
  const attempt = { entry: { runId: 'inert-run-data' }, prepared: { outbound: { requestPath: '/chat/completions' } } };
  return { root, refs, artifacts, initial, trust, stop, signals,
    run: () => invoke.call(context, undefined, undefined, attempt, stop.signal) };
}

test('a previously cancelled broker preparation starts no signed-image, CAS or transport work', async t => {
  const f = await fixture(t), reason = new Error('original reader is closing'); f.stop.abort(reason);
  await assert.rejects(f.run(), error => error === reason); assert.deepEqual(f.signals, []);
});

test('successful broker preparation retains every original binding and full trust-store byte read', async t => {
  const f = await fixture(t), result = await f.run();
  assert.deepEqual(f.signals, [f.stop.signal]); assert.deepEqual(result.initial, f.initial);
  assert.deepEqual(result.frozen, f.refs.map((_ref, index) => ({ kind: 'inert-binding-data', index })));
  assert.deepEqual(result.trustStoreBytes, await f.artifacts.readBytes(f.trust.ref));
});

for (const failClose of [false, true]) test(`cancelled broker preparation joins every issued real CAS descriptor${failClose ? ' and preserves retirement failure' : ''}`, async t => {
  const f = await fixture(t), entered = gate(), release = gate(), reason = new Error('original prepared reader cancelled');
  const retirement = new Error('actual closed CAS file reported failure'), open = fs.open.bind(fs), active = new Set<object>();
  let opened = 0, closed = 0, gated = 0, settled = false;
  const issued = new Set<string>();
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args); opened++; active.add(handle);
    const actualClose = handle.close.bind(handle), actualRead = handle.read.bind(handle);
    const index = f.refs.findIndex(ref => args[0] === path.join(f.root, ref));
    if (index >= 0) {
      issued.add(f.refs[index]!);
      t.mock.method(handle, 'read', async (...values: Parameters<typeof handle.read>) => {
        if (++gated === 4) entered.release(); await release.promise; return actualRead(...values);
      });
    }
    t.mock.method(handle, 'close', async () => {
      await actualClose(); assert(active.delete(handle)); closed++;
      if (failClose && index === 1) throw retirement;
    });
    return handle;
  });
  const pending = f.run(); void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await entered.promise; f.stop.abort(reason); await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(settled, false); assert(active.size > 0); assert.equal(issued.size, 4);
    release.release();
    await assert.rejects(pending, error => failClose ? error instanceof ResourceRetirementError && error.cause === retirement : error === reason);
    assert.equal(issued.size, 4, 'cancelled first wave never starts the two queued binding reads');
    assert.equal(active.size, 0); assert.equal(opened, closed);
  } finally { release.release(); await Promise.allSettled([pending]); assert.equal(active.size, 0); assert.equal(opened, closed); }
});

test('the signed broker loader passes preparation cancellation through both complete original revalidations', async t => {
  const source = await parsed('installed-runtime.ts'), method = methods(source, 'loadModelBroker'), bodies = method.body!.getText(source);
  // Skip the already-loaded inert data node; no dlopen or native factory can run.
  const entered = gate(), release = gate(), stop = new AbortController(), reason = new Error('original loader cancelled');
  let calls = 0, joined = false;
  const invoke = expression(`return (${method.getText(source).replace(/^loadModelBroker/u, 'async function')});`, {
    enqueue: (operation: () => Promise<unknown>) => operation(), assertInstalledModelBrokerProcess: () => {},
    modelBroker: Object.freeze({ kind: 'inert-previously-loaded-data' }),
    checkedRevalidate: async (signal?: AbortSignal) => {
      assert.equal(signal, stop.signal); calls++; entered.release(); await release.promise; joined = true; signal?.throwIfAborted();
    }
  }) as (signal?: AbortSignal) => Promise<unknown>;
  const pending = invoke(stop.signal); await entered.promise; stop.abort(reason); release.release();
  await assert.rejects(pending, error => error === reason); assert.equal(joined, true); assert.equal(calls, 1);
  assert.equal((bodies.match(/await checkedRevalidate\(preparationSignal\)/gu) ?? []).length, 2,
    'successful cached and new module loads keep both full original checks');
});

test('credential preparation forwards the original cancellation before entering any native scope or business callback', async () => {
  const source = await parsed('installed-runtime.ts'), method = methods(source, 'credentialScope'), scope = credentialScope(source);
  const entered = gate(), release = gate(), stop = new AbortController(), reason = new Error('original credential preparation cancelled');
  let loaderJoined = false, touched = false;
  const invoke = expression(`${scope.getText(source)}
    return ({${method.getText(source)}}).credentialScope;`, {
    enqueue: (operation: () => Promise<unknown>) => operation(), isMainThread: true, isSea: () => true,
    process: { versions: { node: '24.21.0' } }, rememberRetirement: () => {},
    loadSelectedNative: async (signal?: AbortSignal) => {
      assert.equal(signal, stop.signal); entered.release(); await release.promise;
      loaderJoined = true; signal?.throwIfAborted(); throw new Error('a cancelled loader cannot produce a native object');
    },
    withHeldCredentialNativeScope: () => { touched = true; throw new Error('no native scope exists in this data fixture'); }
  }) as (operation: () => Promise<void>, signal?: AbortSignal) => Promise<unknown>;
  const pending = invoke(async () => { touched = true; }, stop.signal);
  try {
    await Promise.race([entered.promise, pending]); stop.abort(reason); release.release();
    await assert.rejects(pending, error => error === reason);
    assert.equal(loaderJoined, true); assert.equal(touched, false);
  } finally { release.release(); await Promise.allSettled([pending]); }
});

test('native transport ownership is the cancellation boundary: claim, response, fence and result custody remain raw', async () => {
  const source = await parsed('store.ts'), method = methods(source, 'dispatchInstalledModelOwned'), body = method.getText(source);
  const transport = body.indexOf('transport = broker.prepareModelTransport('), registered = body.indexOf('this.modelTransports.set(runId, transport);', transport);
  const callback = method.body!.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(value => value.name.getText(source) === 'dispatch'));
  assert(callback && ts.isVariableStatement(callback));
  const dispatch = callback.declarationList.declarations[0]!.initializer;
  assert(dispatch && ts.isArrowFunction(dispatch) && ts.isBlock(dispatch.body));
  const cancel = dispatch.body.statements.findIndex(node => node.getText(source) === 'preparationSignal.throwIfAborted();');
  const ownedTry = dispatch.body.statements.findIndex(node => ts.isTryStatement(node));
  assert(cancel >= 0 && ownedTry > cancel, 'cancelled pure preparation does not enter raw failPreparation settlement');
  assert(transport >= 0 && registered > transport);
  assert(!body.slice(transport).includes('preparationSignal.throwIfAborted()'));
  for (const original of [
    'claimInvocationDispatch(this.driver, this.artifacts, this.owner,',
    'const cut = await readModelClaimCut(this.driver, this.artifacts, prepared);',
    'await this.settleInstalledModelCompletion(runId, agent)',
    'await this.settleInstalledModelClosure(runId)', 'transport.releaseDispatchFence()',
    'failInvocationBeforeDispatch(this.driver, this.artifacts, this.owner,',
    'return await withCredentialAuthorityLock(selected, dispatch, preparationSignal)'
  ]) assert(body.includes(original), original);
  const runtime = await parsed('installed-runtime.ts'), scope = credentialScope(runtime).getText(runtime);
  const before = scope.indexOf('await checkedRevalidate(preparationSignal); credential.assertHeld();');
  const invoke = scope.indexOf('await runInstalledCredentialAuthority(physical, operation);');
  const after = scope.indexOf('await checkedRevalidate(); credential.assertHeld();');
  assert(before >= 0 && invoke > before && after > invoke);
  assert.match(scope, /const result = await runInstalledCredentialAuthority\(physical, operation\);\s+await checkedRevalidate\(\); credential\.assertHeld\(\);/u);
  assert.equal((scope.match(/preparationSignal/gu) ?? []).length, 5,
    'only loader/precallback checks use cancellation; original scope/result finalizers remain unchanged');
  assert(!scope.includes('Promise.race') && !methods(runtime, 'credentialScope').getText(runtime).includes('Promise.race') && !body.includes('Promise.race'));
});


test('successful cached broker preparation keeps both original complete image revalidations', async t => {
  const f = await fixture(t), source = await parsed('installed-runtime.ts'), method = methods(source, 'loadModelBroker');
  const original = Object.freeze({ kind: 'inert-previously-loaded-data' }); let calls = 0;
  const invoke = expression(`return (${method.getText(source).replace(/^loadModelBroker/u, 'async function')});`, {
    enqueue: (operation: () => Promise<unknown>) => operation(), assertInstalledModelBrokerProcess: () => {}, modelBroker: original,
    checkedRevalidate: async (signal?: AbortSignal) => {
      calls++; assert.equal(signal, f.stop.signal);
      assert.deepEqual(await f.artifacts.withReadSignal(signal!).readBytes(f.trust.ref), await f.artifacts.readBytes(f.trust.ref));
    }
  }) as (signal?: AbortSignal) => Promise<unknown>;
  assert.equal(await invoke(f.stop.signal), original); assert.equal(calls, 2);
});

test('model diagnostic phases precede their exact original scheduler and dispatch operations', async () => {
  const source = await parsed('store.ts'), drive = methods(source, 'driveInstalledRun').getText(source);
  const pairs = [
    ['drive_prior_read', 'const prior = await agent.readModelAttempt(readSignal);'],
    ['drive_worker_activate', 'current = await native.activateCurrentWorker({ expectedRunRevision: current.revision });'],
    ['drive_model_prepare', 'prepared = await agent.prepareModel(']
  ];
  for (const [phase, operation] of pairs) {
    const label = `this.installedRunPhases.set(runId, '${phase}');`, at = drive.indexOf(label);
    assert(at >= 0 && drive.indexOf(operation!, at) > at, phase);
    assert.equal(drive.split(label).length, 2);
  }
  assert(drive.includes('this.dispatchInstalledModel(native, agent, prepared, readSignal)'));
  const owned = methods(source, 'dispatchInstalledModelOwned').getText(source);
  for (const [phase, operation] of [
    ['drive_broker_prepare', 'const broker = await loadInstalledModelBroker(selected, preparationSignal);'],
    ['drive_credential_prepare', 'return await withCredentialAuthorityLock(selected, dispatch, preparationSignal);'],
    ['drive_model_claim', 'claimed = await claimInvocationDispatch('],
    ['drive_model_release', 'await gate(() => transport!.connect(binding));']
  ]) {
    const at = owned.indexOf(`this.installedRunPhases.set(runId, '${phase}');`);
    assert(at >= 0 && owned.indexOf(operation!, at) > at, phase);
  }
  const close = methods(source, 'beginClose').getText(source);
  assert(close.includes('scope.readAbort?.abort(')); assert(close.includes('for (const transport of this.modelTransports.values())'));
  assert(close.includes('void transport.close().catch(() => {});'));
});
