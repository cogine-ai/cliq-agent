import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { promises as fs, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import ts from 'typescript';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { joinResourceOperations, ResourceRetirementError } from './errors.js';

// Wiring checks are deliberately not StateOwner, Run or native evidence. The
// filesystem regression below delays only a genuinely completed CAS return.
const source = (name: string) => readFileSync(new URL(name, import.meta.url), 'utf8');
function between(text: string, start: string, end: string): string {
  const first = text.indexOf(start), last = text.indexOf(end, first);
  assert(first >= 0 && last > first, 'the original production scope must exist');
  return text.slice(first, last);
}

test('installed waits retain reconciliation but let an actually registered Stop reach the original input or approval drain', () => {
  // Evaluate only the actual pure branch condition. No fixture can turn on
  // supportsInstalledRuns, construct a launcher or mint a native authority.
  const text = source('./store.ts'), file = ts.createSourceFile('store.ts', text, ts.ScriptTarget.Latest, true);
  let method: ts.MethodDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node) && node.name.getText(file) === 'driveInstalledRun') method = node;
    ts.forEachChild(node, visit);
  }; visit(file); assert(method?.body);
  const guards: ts.IfStatement[] = [];
  const choose = (node: ts.Node) => {
    if (ts.isIfStatement(node) && ts.isReturnStatement(node.thenStatement) &&
        /^current\.status === 'waiting'/u.test(node.expression.getText(file))) guards.push(node);
    ts.forEachChild(node, choose);
  }; choose(method.body); assert.equal(guards.length, 1);
  const holds = new Function('current', `return (${guards[0]!.expression.getText(file)});`) as (current: unknown) => boolean;
  for (const waitingReason of ['input', 'approval']) {
    assert.equal(holds({ status: 'waiting', waitingReason }), true);
    assert.equal(holds({ status: 'waiting', waitingReason, stopIntentRef: 'original-registered-ref' }), false);
  }
  assert.equal(holds({ status: 'waiting', waitingReason: 'reconciliation', stopIntentRef: 'original-registered-ref' }), true);
  assert.equal(holds({ status: 'queued', stopIntentRef: 'original-registered-ref' }), false);
  assert.match(method.body.getText(file), /if \(settled\.run\.status !== 'waiting'\) continue;\s*return;/u,
    'a genuine still-pending child wait must return to maintenance without attempting terminal quiescence');
});

test('publication admission scopes its three final reads but preserves original joined publications and owner binding', () => {
  const body = between(source('./publication-invocation.ts'), 'export async function preparePublicationInvocation(', 'type MaintenanceInput =');
  assert.match(body, /prepareValidatedInvocation\(driver, reads, owner,/u,
    'the original final invocation preflight must receive the existing read cancellation view');
  assert.match(body, /const metadata = await joinResourceOperations\(\[artifacts\.publishCanonical/u);
  assert.equal(body.match(/artifacts\.publishCanonical\(/gu)?.length, 3, 'all three original durable publications remain on the raw catalog');
  assert.doesNotMatch(body, /reads\.publishCanonical/u);
  assert.match(body, /const held: Binding = \{ mode: 'forward', driver, artifacts, reads, owner,/u,
    'the genuine retained owner must keep its original raw catalog');
  assert.match(body, /root\.assertHeld\(\); input\.signal\?\.throwIfAborted\(\);/u);
  assert.match(body, /validate\(connection, run, attempt, now\) \{\s*assertCut\(connection\);/u,
    'the original transaction still validates the actual owner cut and cancellation');
});

// Bind only the caller's actual catalog argument and each of the reducer's
// original three read expressions. The plain ref holders below are not a Run,
// StateOwner, invocation input, SQL transaction or native authority.
function publicationAdmissionRead(stage: 'request' | 'grant' | 'spec'):
  (artifacts: ArtifactCatalog, reads: ArtifactCatalog, ref: string) => Promise<unknown> {
  const forward = between(source('./publication-invocation.ts'), 'export async function preparePublicationInvocation(', 'type MaintenanceInput =');
  const caller = ts.createSourceFile('publication-admission-catalog-data.ts', forward, ts.ScriptTarget.Latest, true);
  const invocations: ts.CallExpression[] = [];
  const findCall = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(caller) === 'prepareValidatedInvocation') invocations.push(node);
    ts.forEachChild(node, findCall);
  };
  findCall(caller); assert.equal(invocations.length, 1, 'use only the original forward publication admission call');
  const argument = invocations[0]!.arguments[1]!;
  assert(ts.isIdentifier(argument) && ['artifacts', 'reads'].includes(argument.text), 'the actual catalog argument must remain a fixed local binding');
  const choose = new Function('artifacts', 'reads', `return ${argument.getText(caller)};`);
  const reducer = ts.createSourceFile('invocation-read-data.ts', source('./reducers/invocation.ts'), ts.ScriptTarget.Latest, true);
  const body = reducer.statements.find((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === 'prepareValidatedInvocation')?.body;
  assert(body, 'the original reducer body must exist');
  const signatures = { request: 'artifacts.readBytes(input.requestRef)', grant: 'artifacts.readBytes(input.grantRef)',
    spec: 'artifacts.readCanonical(initialRun.specRef)' };
  const expressions: ts.CallExpression[] = [];
  const findRead = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.getText(reducer) === signatures[stage]) expressions.push(node);
    ts.forEachChild(node, findRead);
  };
  findRead(body); assert.equal(expressions.length, 1, 'execute one original read expression, never the reducer or its authority checks');
  const output = ts.transpileModule(`return ${expressions[0]!.getText(reducer)};`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const read = new Function('artifacts', 'input', 'initialRun', output);
  return (artifacts, reads, ref) => read(choose(artifacts, reads), { requestRef: ref, grantRef: ref }, { specRef: ref }) as Promise<unknown>;
}

for (const stage of ['request', 'grant', 'spec'] as const) for (const fault of ['cancel', 'retirement'] as const)
  test(`publication admission ${stage} read joins its genuine FD and original return before exposing ${fault}`, async t => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-publication-admission-read-'));
    t.after(() => fs.rm(home, { recursive: true, force: true }));
    const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
    const cas = new ContentAddressedStore(root), catalog = new ArtifactCatalog(cas);
    const { ref } = await catalog.publishCanonical({ diagnosticOnly: true, stage, value: 'inert complete CAS bytes, never authority' }, 'cliq-read-join-data-v1');
    const owner = new AbortController(), reason = new Error('the original publication preflight was revoked');
    const closeFailure = new Error('the actual publication preflight root closed but its report is uncertain');
    const gate = () => { let release!: () => void; return { promise: new Promise<void>(resolve => { release = resolve; }), release }; };
    const closing = gate(), closeGate = gate(), returned = gate(), returnGate = gate();
    const active = new Set<object>(), open = fs.open, originalRead = cas.read.bind(cas);
    let opened = 0, closed = 0, settled = false, actualCloseFailure = false, originalReadFailure: unknown;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args); active.add(handle); opened++;
      const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => {
        if (args[0] === root) { closing.release(); await closeGate.promise; }
        await close(); assert.equal(active.delete(handle), true); closed++;
        if (fault === 'retirement' && args[0] === root) { actualCloseFailure = true; throw closeFailure; }
      });
      return handle;
    });
    t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => {
      let bytes: Buffer | undefined, failed: { error: unknown } | undefined;
      try { bytes = await originalRead(...args); } catch (error) { originalReadFailure = error; failed = { error }; }
      assert.equal(active.size, 0); returned.release(); await returnGate.promise;
      if (failed) throw failed.error; return bytes!;
    });
    const work = publicationAdmissionRead(stage)(catalog, catalog.withReadSignal(owner.signal), ref);
    void work.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.race([closing.promise, work.then(() => { throw new Error('the actual preflight root close gate was bypassed'); })]);
      assert.equal(opened, 2); assert.equal(closed, 1); assert.equal(active.size, 1, 'the actual original root descriptor remains open');
      owner.abort(reason); await setImmediate();
      assert.equal(settled, false, 'cancellation must not detach the original descriptor');
      closeGate.release(); await returned.promise;
      assert.equal(opened, 2); assert.equal(closed, 2); assert.equal(active.size, 0);
      assert.equal(settled, false, 'the original completed CAS return still belongs to the same preflight');
      returnGate.release();
      await assert.rejects(work, error => fault === 'cancel' ? error === reason
        : error === originalReadFailure && error instanceof ResourceRetirementError && error.cause === closeFailure,
      'the original cancellation reason or higher-priority real CAS retirement failure must survive');
      assert.equal(actualCloseFailure, fault === 'retirement'); assert.equal(active.size, 0);
    } finally {
      closeGate.release(); returnGate.release(); await Promise.allSettled([work]);
      assert.equal(active.size, 0); t.mock.restoreAll();
    }
  });

test('installed admission scopes only its read-only CAS work and retains original publication and transaction boundaries', () => {
  const submit = between(source('./store.ts'), 'private async submitInstalledRunOwned(', '/** One bounded production lane,');
  assert.match(submit, /const reads = this\.artifacts\.withReadSignal\(signal\)/u);
  assert.doesNotMatch(submit, /validateControlChannelClosure\(this\.artifacts|readSourceInspectionErrorResponse\(this\.artifacts/u);
  const assembly = between(source('./installed-run.ts'), 'export async function assembleInstalledRun(', '/** Genuine-brand-first admission friend.');
  assert.match(assembly, /const reads = signal \? artifacts\.withReadSignal\(signal\) : artifacts/u);
  assert.doesNotMatch(assembly, /readCanonicalArtifact(?:<[^\n]+?>)?\(artifacts|validateControlChannelClosure\(artifacts|materialFor\(installed, artifacts/u);
  assert.match(assembly, /captureInstalledWorkspaceInstructions\(root, artifacts,/u);
  assert.match(assembly, /await prepareInstalledVerifierAssembly\(driver, reads, owner,/u);
  const verifier = source('./verifier-admission.ts');
  const preparation = between(verifier, 'export async function prepareInstalledVerifierAssembly(', 'export async function prepareVerifierConsumption(');
  assert.match(preparation, /await resolveVerifierSpec\(driver, artifacts, owner, runtime, input, undefined, signal, onPreparationPhase\)/u);
  assert.match(preparation, /await publishVerifierAssembly\(artifacts, composed, input\.assembly, signal\)/u);
  const publication = between(verifier, 'export async function publishVerifierAssembly(', '/** Deterministic command/environment construction,');
  assert.match(publication, /await artifacts\.publishCanonical\(assembly, assembly\.format\)/u);
  assert.match(publication, /await artifacts\.publishCanonicalFour\(\[/u);
  const catalog = source('./artifacts.ts');
  const group = between(catalog, '  async publishCanonicalFour(', '  async publishChunks(');
  assert.match(group, /await this\.cas\.publishFour\(/u);
  assert.doesNotMatch(group, /this\.readSignal|throwIfAborted/u,
    'the temporary read view cannot cancel or abandon the actual publication group');
  const admission = source('./reducers/admission.ts');
  const replay = between(admission, 'export async function replayInstalledRunAdmission(', 'type InstalledAdmission =');
  const internal = admission.slice(admission.indexOf('async function admitRunInternal('));
  for (const body of [replay, internal]) {
    assert.match(body, /const reads = signal \? artifacts\.withReadSignal\(signal\) : artifacts/u);
    assert.doesNotMatch(body, /readCanonicalArtifact(?:<[^\n]+?>)?\(artifacts|artifacts\.(?:readBytes|readCanonical|describe)\(|validateControlChannelClosure\(artifacts/u);
    assert.match(body, /await artifacts\.publishCanonical\(/u, 'read cancellation cannot replace the original publication catalog');
  }
  assert.match(internal, /driver\.transaction\(\(connection\) => \{\s*signal\?\.throwIfAborted\(\);/u,
    'the original final-transaction signal check must remain in place');
});

test('source capture preflight scopes reads without retaining an aborted catalog for genuine birth and retirement', () => {
  const store = between(source('./store.ts'), '  async captureSubmittedSource(', '  claimInvocationDispatch(');
  assert.match(store, /validateControlChannelClosure\(this\.artifacts\.withReadSignal\(abort\.signal\), this\.owner, input\.identity\)/u);
  assert.match(store, /return captureSubmittedSource\(this\.driver, this\.artifacts, this\.owner,/u,
    'the source owner must receive the original catalog for later actual result registration');
  const owner = source('./source-inspection-owner.ts');
  const replay = between(owner, 'export async function replaySubmittedSource(', 'async function publishSourceRetirement(');
  assert.match(replay, /const reads = signal \? artifacts\.withReadSignal\(signal\) : artifacts/u);
  assert.doesNotMatch(replay, /readCanonicalArtifact(?:<[^\n]+?>)?\(artifacts|validateControlChannelClosure\(artifacts|readRetainedSourceInspectionTarget\(artifacts|readDeliveryCaptureTopology\(artifacts|readSourceInspectionRetirement\(driver, artifacts/u);
  const capture = owner.slice(owner.indexOf('export async function captureSubmittedSource('));
  const preflight = capture.slice(0, capture.indexOf('  const resources:'));
  assert.match(preflight, /const reads = signal \? artifacts\.withReadSignal\(signal\) : artifacts/u);
  assert.doesNotMatch(preflight, /validateControlChannelClosure\(artifacts|readVerifiedDeliverySource\(driver, artifacts|resolveDeliverySourceCapture\(driver, artifacts/u);
  assert.match(capture, /createVerifiedSourceInspectionTarget\(\{ driver, artifacts, owner,/u);
  assert.match(capture, /reserveSourceInspectionAttempt\(driver, artifacts, owner, target, stage\)/u);
  const target = between(source('./source-target.ts'), 'export async function createVerifiedSourceInspectionTarget(', '/** Shared retained-data binding,');
  assert.match(target, /const reads = context\.signal \? artifacts\.withReadSignal\(context\.signal\) : artifacts/u);
  const validation = target.slice(0, target.indexOf('  const original = await artifacts.publishCanonical('));
  assert.doesNotMatch(validation, /readCanonicalArtifact(?:<[^\n]+?>)?\(artifacts|validateControlChannelClosure\(artifacts|resolveDeliverySourceCapture\(driver, artifacts|readVerifierRequestIdentities\(driver, artifacts/u);
  assert.match(target, /verifiedTargets\.set\(result, \{ driver, artifacts, owner,/u,
    'the original raw catalog, not the temporary read view, must remain in the genuine WeakMap binding');
  assert.match(target, /await recheckVerifiedSourceInspectionTarget\(owner, result\)/u);
});

// Execute the exact workspace-object read expression only, not its decoder,
// target constructor, WeakMap registration, native handles or authority checks.
function sourceTargetPreflightRead(): (artifacts: ArtifactCatalog, reads: ArtifactCatalog, ref: string) => Promise<unknown> {
  const body = between(source('./source-target.ts'), 'export async function createVerifiedSourceInspectionTarget(', '/** Shared retained-data binding,');
  const parsed = ts.createSourceFile('source-target-read-data.ts', body, ts.ScriptTarget.Latest, true);
  const expressions: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'readCanonicalArtifact' &&
        node.arguments[1]?.getText(parsed) === 'session.workspaceIdentityRef') expressions.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(expressions.length, 1);
  const output = ts.transpileModule(`return ${expressions[0]!.getText(parsed)};`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const read = new Function('artifacts', 'reads', 'session', 'readCanonicalArtifact', output);
  return (artifacts, reads, ref) => read(artifacts, reads, { workspaceIdentityRef: ref }, readCanonicalArtifact) as Promise<unknown>;
}

for (const fault of ['cancel', 'retirement'] as const)
  test(`source target preflight joins its real CAS read before exposing ${fault}`, async t => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-source-preflight-read-'));
    t.after(() => fs.rm(home, { recursive: true, force: true }));
    const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
    const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
    const { ref } = await artifacts.publishCanonical({ diagnosticOnly: true, value: 'plain read bytes, never workspace authority' }, 'cliq-read-join-data-v1');
    const owner = new AbortController(), reason = new Error('the original source preflight read was revoked');
    const closeFailure = new Error('the original source preflight root closed but its report is uncertain');
    const open = fs.open, read = cas.read.bind(cas), active = new Set<object>();
    let enter!: () => void, release!: () => void, actualRootCloseFailure = false, joined = false;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args); active.add(handle); const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => {
        await close(); assert.equal(active.delete(handle), true);
        if (fault === 'retirement' && args[0] === root) { actualRootCloseFailure = true; throw closeFailure; }
      });
      return handle;
    });
    t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => {
      let bytes: Buffer | undefined, failed: { error: unknown } | undefined;
      try { bytes = await read(...args); } catch (error) { failed = { error }; }
      assert.equal(active.size, 0); enter(); await gate;
      if (failed) throw failed.error; return bytes!;
    });
    const work = sourceTargetPreflightRead()(artifacts, artifacts.withReadSignal(owner.signal), ref);
    void work.then(() => { joined = true; }, () => { joined = true; });
    try {
      await entered; owner.abort(reason);
      assert.equal(joined, false, 'revocation is not an early-return or resource-join receipt');
      release();
      await assert.rejects(work, error => fault === 'cancel' ? error === reason
        : error instanceof ResourceRetirementError && error.cause === closeFailure);
      assert.equal(actualRootCloseFailure, fault === 'retirement'); assert.equal(active.size, 0);
    } finally { release(); await Promise.allSettled([work]); t.mock.restoreAll(); }
  });

// Execute only the original metadata-read expression over genuine CAS data.
// This creates no admission, Run, StateOwner, native proof or authority seam.
function admissionMetadata(): (input: Record<string, unknown>, sourceManifest: { entriesRef: string }, reads: ArtifactCatalog) => Promise<unknown> {
  const parsed = ts.createSourceFile('admission-read-data.ts', source('./reducers/admission.ts'), ts.ScriptTarget.Latest, true);
  const expressions: ts.Expression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'referencedMetadata' && node.initializer)
      expressions.push(node.initializer);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(expressions.length, 1);
  const output = ts.transpileModule(`return (async () => ${expressions[0]!.getText(parsed)})();`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const decode = new Function('input', 'sourceManifest', 'artifacts', 'reads', 'joinResourceOperations', output);
  return (input, manifest, reads) => decode(input, manifest, reads, reads, joinResourceOperations) as Promise<unknown>;
}

// Execute only the original delivery item-read expression. These plain CAS
// payloads are not a RecoveryClosure, delivery authority or native evidence.
function deliveryAuthorizationItems(): (items: { payloadRef: string }[], artifacts: ArtifactCatalog) => Promise<unknown> {
  const body = between(source('./delivery-approval.ts'), 'export async function readDeliveryAuthorization(', 'export async function readDeliveryPolicyDenial(');
  const parsed = ts.createSourceFile('delivery-authorization-read-data.ts', body, ts.ScriptTarget.Latest, true);
  const expressions: ts.Expression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'decoded' && node.initializer)
      expressions.push(node.initializer);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(expressions.length, 1);
  const output = ts.transpileModule(`return (async () => ${expressions[0]!.getText(parsed)})();`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const read = new Function('cut', 'artifacts', 'readCanonicalArtifact', 'joinResourceOperations', output);
  return (items, artifacts) => read({ items }, artifacts, readCanonicalArtifact, joinResourceOperations) as Promise<unknown>;
}

for (const fault of ['ordinary', 'cancel', 'retirement'] as const)
  test(`delivery authorization item reads join real pending descriptors and preserve ${fault}`, async t => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-delivery-read-join-'));
    t.after(() => fs.rm(home, { recursive: true, force: true }));
    const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
    const cas = new ContentAddressedStore(root), catalog = new ArtifactCatalog(cas), refs: string[] = [];
    for (let index = 0; index < 3; index++) refs.push((await catalog.publishCanonical({ diagnosticOnly: true, index }, 'cliq-read-join-data-v1')).ref);
    const owner = new AbortController(), reason = new Error('the original delivery read owner closed');
    const ordinaryFailure = new Error('the original first delivery item read failed');
    const closeFailure = new Error('the second actual root close reported retirement uncertainty');
    const call = new AsyncLocalStorage<string>(), active = new Set<object>(), open = fs.open, read = cas.read.bind(cas);
    const gate = () => { let release!: () => void; return { promise: new Promise<void>(resolve => { release = resolve; }), release }; };
    const firstReturned = gate(), thirdReturned = gate(), secondClosing = gate(), closeGate = gate();
    const returns = [gate(), gate(), gate()], producers: Promise<Buffer>[] = [], failures = new Map<string, unknown>();
    let opened = 0, closed = 0, outerJoined = false, actualRootCloseFailure = false;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args), ref = call.getStore(); active.add(handle); opened++;
      const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => {
        if (ref === refs[1] && args[0] === root) { secondClosing.release(); await closeGate.promise; }
        await close(); assert.equal(active.delete(handle), true); closed++;
        if (fault === 'retirement' && ref === refs[1] && args[0] === root) {
          actualRootCloseFailure = true; throw closeFailure;
        }
      });
      return handle;
    });
    t.mock.method(cas, 'read', (...args: Parameters<typeof cas.read>) => {
      const operation = call.run(args[0], async () => {
        let bytes: Buffer | undefined, failed: { error: unknown } | undefined;
        try { bytes = await read(...args); } catch (error) { failed = { error }; failures.set(args[0], error); }
        const index = refs.indexOf(args[0]);
        if (index === 0) firstReturned.release(); if (index === 2) thirdReturned.release();
        await returns[index]!.promise;
        if (failed) throw failed.error;
        if (fault === 'ordinary' && index === 0) throw ordinaryFailure;
        return bytes!;
      });
      producers.push(operation); return operation;
    });
    const work = deliveryAuthorizationItems()(refs.map(payloadRef => ({ payloadRef })), catalog.withReadSignal(owner.signal));
    void work.then(() => { outerJoined = true; }, () => { outerJoined = true; });
    try {
      await Promise.race([Promise.all([firstReturned.promise, secondClosing.promise, thirdReturned.promise]),
        work.then(() => { throw new Error('the original three CAS reads bypassed their genuine descriptor/return gates'); })]);
      assert.equal(producers.length, 3); assert.equal(opened, 6); assert.equal(closed, 5); assert.equal(active.size, 1);
      if (fault !== 'ordinary') owner.abort(reason);
      returns[0]!.release(); await setImmediate();
      assert.equal(outerJoined, false, 'the first failure cannot release the owner with another actual root descriptor still open');
      assert.equal(active.size, 1);
      closeGate.release(); returns[1]!.release();
      await Promise.allSettled(producers.slice(0, 2)); await setImmediate();
      assert.equal(active.size, 0); assert.equal(closed, 6);
      assert.equal(outerJoined, false, 'the final original CAS return still belongs to the same read group');
      returns[2]!.release();
      await assert.rejects(work, error => fault === 'retirement'
        ? error === failures.get(refs[1]!) && error instanceof ResourceRetirementError && error.cause === closeFailure
        : error === (fault === 'ordinary' ? ordinaryFailure : reason));
      assert.equal(actualRootCloseFailure, fault === 'retirement');
      assert.equal(active.size, 0); await setImmediate();
    } finally {
      closeGate.release(); returns.forEach(value => value.release());
      await Promise.allSettled([work, ...producers]); assert.equal(active.size, 0); t.mock.restoreAll();
    }
  });

for (const fault of ['cancel', 'ordinary', 'retirement'] as const)
  test(`admission metadata reads stop queued work and join every issued original CAS sibling before exposing ${fault}`, async t => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-read-join-'));
    t.after(() => fs.rm(home, { recursive: true, force: true }));
    const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
    const cas = new ContentAddressedStore(root), catalog = new ArtifactCatalog(cas), refs: string[] = [];
    for (let index = 0; index < 9; index++) refs.push((await catalog.publishCanonical({ diagnosticOnly: true, index }, 'cliq-read-join-data-v1')).ref);
    const names = ['assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef', 'sourceProjectionRef', 'frozenIgnoreRulesRef', 'baseWorkspaceManifestRef'];
    const input = { ...Object.fromEntries(names.map((name, index) => [name, refs[index]!])), credentialGrantRefs: [refs[8]!] };
    const owner = new AbortController(), reason = new Error('the original admission read was revoked');
    const ordinaryFailure = new Error('the original first read failed after its actual descriptors joined');
    const closeFailure = new Error('the original second root closed but its retirement report is uncertain');
    const call = new AsyncLocalStorage<string>(), active = new Set<object>(), open = fs.open, read = cas.read.bind(cas);
    const gates = refs.map(() => { let release!: () => void; return { promise: new Promise<void>(resolve => { release = resolve; }), release }; });
    let enter!: () => void, returned = 0, outerJoined = false, actualRootCloseFailure = false;
    const entered = new Promise<void>(resolve => { enter = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args), ref = call.getStore(); active.add(handle);
      const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => {
        await close(); assert.equal(active.delete(handle), true);
        if (fault === 'retirement' && ref === refs[1] && args[0] === root) {
          actualRootCloseFailure = true; throw closeFailure;
        }
      });
      return handle;
    });
    t.mock.method(cas, 'read', (...args: Parameters<typeof cas.read>) => call.run(args[0], async () => {
      let bytes: Buffer | undefined, failed: { error: unknown } | undefined;
      try { bytes = await read(...args); } catch (error) { failed = { error }; }
      if (++returned === 4) enter();
      await gates[refs.indexOf(args[0])]!.promise;
      if (failed) throw failed.error;
      if (fault === 'ordinary' && args[0] === refs[0]) throw ordinaryFailure;
      return bytes!;
    }));
    const work = admissionMetadata()(input, { entriesRef: refs[7]! }, catalog.withReadSignal(owner.signal));
    void work.then(() => { outerJoined = true; }, () => { outerJoined = true; });
    try {
      await Promise.race([entered, work.then(() => { throw new Error('the original first four CAS return gates were bypassed'); })]);
      assert.equal(returned, 4, 'later metadata reads must remain queued behind the original four issued callbacks');
      assert.equal(active.size, 0, 'all actual CAS descriptors join before the original return gates release');
      if (fault !== 'ordinary') owner.abort(reason);
      gates[0]!.release(); await setImmediate();
      assert.equal(outerJoined, false, 'the first failure cannot detach three pending original metadata reads');
      gates.slice(1).forEach(gate => gate.release());
      await assert.rejects(work, error => fault === 'retirement'
        ? error instanceof ResourceRetirementError && error.cause === closeFailure
        : error === (fault === 'ordinary' ? ordinaryFailure : reason));
      assert.equal(actualRootCloseFailure, fault === 'retirement'); assert.equal(active.size, 0);
      assert.equal(returned, 4, 'failure or cancellation must not dispatch the remaining five original metadata refs');
    } finally { gates.forEach(gate => gate.release()); await Promise.allSettled([work]); t.mock.restoreAll(); }
  });

for (const publisher of ['original', 'read_view'] as const)
  test(`read cancellation cannot truncate the ${publisher} catalog's genuine durable publication`, async t => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-publish-join-'));
    t.after(() => fs.rm(home, { recursive: true, force: true }));
    const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
    const catalog = new ArtifactCatalog(new ContentAddressedStore(root));
    const owner = new AbortController(), reason = new Error('the original read owner closed during the actual publication write');
    const reads = catalog.withReadSignal(owner.signal), open = fs.open, active = new Set<object>();
    let originalWrites = 0;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args); active.add(handle);
      const close = handle.close.bind(handle), write = handle.writeFile.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); assert.equal(active.delete(handle), true); });
      t.mock.method(handle, 'writeFile', async (...values: Parameters<typeof handle.writeFile>) => {
        const result = await write(...values);
        originalWrites++;
        if (originalWrites === 1) owner.abort(reason);
        else assert.equal(owner.signal.aborted, true, 'later original chunks must persist after read cancellation');
        return result;
      });
      return handle;
    });
    try {
      const value = { diagnosticOnly: true, publisher, text: 'complete retained publication bytes '.repeat(4096) };
      const result = await (publisher === 'original' ? catalog : reads).publishCanonical(value, 'cliq-read-cancellation-data-v1');
      assert.equal(originalWrites, 3, 'all three bounded original writes complete after the first one cancels the read view');
      assert.equal(owner.signal.aborted, true); assert.equal(active.size, 0, 'publication joins every real descriptor after cancellation');
      await assert.rejects(reads.readBytes(result.ref), error => error === reason);
      assert.deepEqual(await readCanonicalArtifact(catalog, result.ref), value, 'the complete immutable publication remains fully verifiable');
      assert.equal(active.size, 0);
    } finally { t.mock.restoreAll(); }
  });

test('cached Agent reads retain a close-owned signal without cancelling the received model settlement catalog', () => {
  const store = source('./store.ts'), agent = source('./reducers/agent.ts');
  assert.doesNotMatch(agent, /^\s*artifacts =/mu, 'constructor cancellation must not replace the received-result catalog');
  const retain = between(store, 'private retainInstalledAgent(', '/** One joined maintenance owner.');
  assert.match(retain, /const readAbort = new AbortController\(\)/u);
  assert.doesNotMatch(retain, /spec\.operation === 'delivery' \? new AbortController/u);
  assert.match(retain, /this\.installedAgents\.set\(runId, \{ agent, readAbort \}\)/u);
  const modelRead = between(agent, 'readModelAttempt: stateOperation(', 'prepareModel: stateOperation(');
  assert.match(modelRead, /async \(readSignal\?: AbortSignal\)/u);
  assert.match(modelRead, /const reads = readSignal \? artifacts\.withReadSignal\(readSignal\) : artifacts/u);
  assert.match(modelRead, /readRecoveryClosure\(driver, reads, runId\)/u);
  assert.match(modelRead, /reproduceRequest\(closure\.run, request, reads\)/u);
  const prepare = between(agent, 'prepareModel: stateOperation(', 'completeModel: stateOperation(');
  assert.match(prepare, /readSignal\?: AbortSignal/u);
  assert.match(prepare, /agentCut\(driver, reads, runId, expectedRunRevision\)/u);
  assert.match(prepare, /project\(cut\.run, cut\.context, cut\.checkpoint\.contextManifestRef, reads\)/u);
  const complete = agent.slice(agent.indexOf('completeModel: stateOperation('));
  assert.doesNotMatch(complete, /withReadSignal|readSignal|\breads\b/u);
  assert.match(complete, /readCanonicalArtifact<ModelRequestV1>\(artifacts, prepared\.requestRef\)/u);
});

test('the installed driver propagates its retained read lifetime through material and model preparation', () => {
  const store = source('./store.ts'), material = source('./installed-run.ts');
  const drive = between(store, 'private async driveInstalledRun(', 'async cancelInstalledRun(');
  assert.match(drive, /const readSignal = this\.installedAgents\.get\(runId\)\?\.readAbort\?\.signal/u);
  assert.match(drive, /loadInstalledRunMaterial\(\{ selected: this\.installedRuntime!, artifacts: reads, assemblyRef: spec\.assemblyRef,\s*driver: this\.driver, runId, signal: readSignal \}\)/u);
  assert.match(drive, /agent\.readModelAttempt\(readSignal\)/u);
  assert.match(drive, /agent\.prepareModel\(\{ expectedRunRevision: current\.revision, leaseEpoch: current\.leaseEpoch \}, readSignal\)/u);
  const load = between(material, 'export async function loadInstalledRunMaterial(', 'export async function assembleInstalledRun(');
  assert.match(load, /const artifacts = input\.signal \? input\.artifacts\.withReadSignal\(input\.signal\) : input\.artifacts/u);
  assert.match(load, /materialFor\(installed, artifacts, assembly, input\.signal, childOrigin\)/u);
  assert.match(load, /readChildAdmission\(input\.driver!, artifacts, run\.id, \{ signal: input\.signal \}\)/u);
});

test('preparation and recovery bind full CAS reads to their actual task while received checkpoints keep their original catalog', () => {
  const execution = source('./run-execution.ts');
  const activation = between(execution, 'activateCurrentWorker: async value =>', 'executeCurrentNoOpDelivery: async value =>');
  assert.match(activation, /const reads = artifacts\.withReadSignal\(signal\)/u);
  assert.match(activation, /readRecoveryClosure\(driver, reads, runId\)/u);
  const retirement = between(execution, 'resumeCurrentRetirement: async value =>', 'recoverWorker: async value =>');
  assert.match(retirement, /const reads = artifacts\.withReadSignal\(signal\)/u);
  assert.doesNotMatch(retirement, /readRecoveryClosure\(driver, artifacts|readQuarantinedWorkerLaunchClosure\(driver, artifacts/u);
  const recovery = between(execution, 'const inspect = async (run: Run, wait: WorkerDeathWait, signal: AbortSignal)', 'const work = (async () => {\n        if (closed || isClosing())');
  assert.match(recovery, /const reads = artifacts\.withReadSignal\(signal\)/u);
  assert.match(recovery, /requireAgent\(\)\.readModelAttempt\(signal\)/u);
  assert.doesNotMatch(recovery, /readRecoveryClosure\(driver, artifacts|readRetainedWorkerLaunchClosure\(artifacts/u);
  const checkpoint = between(execution, 'function checkpointRetirement(', 'async function retireToCheckpoint(');
  assert.doesNotMatch(checkpoint, /withReadSignal/u);
  assert.match(checkpoint, /readRecoveryClosure\(driver, artifacts, runId\)/u);
});

test('the final candidate and verifier/tool preparation use only their preparing signal, never the received completion signal', () => {
  const final = source('./final-candidate.ts'), verifier = source('./verifier-execution.ts'), tool = source('./reducers/tool.ts');
  const begin = between(final, 'async function begin(', 'let proofInput: ToolCheckpointProof');
  assert.match(begin, /signal\?: AbortSignal/u);
  assert.match(begin, /const reads = signal \? artifacts\.withReadSignal\(signal\) : artifacts/u);
  assert.doesNotMatch(begin, /readRecoveryClosure\(driver, artifacts|readCanonicalArtifact(?:<[^>]+>)?\(artifacts|readModelTurnMaterial\(artifacts/u);
  const preparing = between(verifier, 'prepareVerifier: stateOperation(', 'failVerifierPreparation: stateOperation(');
  assert.match(preparing, /readSignal\?: AbortSignal/u);
  assert.match(preparing, /cut\(input\.expectedRunRevision, readSignal\)/u);
  assert.doesNotMatch(preparing, /readCanonicalArtifact(?:<[^>]+>)?\(artifacts|prepareValidatedInvocation\(driver, artifacts/u);
  const prepareTool = between(tool, 'prepareTool: stateOperation(', 'retireToolSelection: stateOperation(');
  assert.match(prepareTool, /readSignal\?: AbortSignal/u);
  assert.match(prepareTool, /cut\(expectedRunRevision, reads\)/u);
  assert.doesNotMatch(prepareTool, /artifacts\.readBytes|prepareContinuationCommit\(artifacts|prepareValidatedInvocation\(driver, artifacts/u);
  const retiringTool = between(tool, 'retireToolSelection: stateOperation(', 'waitForToolApproval: stateOperation(');
  assert.doesNotMatch(retiringTool, /withReadSignal|readSignal/u,
    'the original physical selection-retirement receipt must join independently of preparation cancellation');
  const execution = source('./run-execution.ts');
  assert.match(execution, /currentAgent\.beginFinalCandidate\(\{ expectedRunRevision \}, signal\)/u);
  assert.match(execution, /continuation\.prepareVerifier\(\{ expectedRunRevision: run\.revision, leaseEpoch: run\.leaseEpoch \}, signal\)/u);
  const parsed = ts.createSourceFile('tool-preparation.ts', execution, ts.ScriptTarget.Latest, true);
  const preparations: ts.CallExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText(parsed) === 'currentAgent' && node.expression.name.text === 'prepareTool') preparations.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed);
  assert.equal(preparations.length, 3, 'queued selection, capacity rollover and activated execution must all retain their preparation lifetime');
  for (const call of preparations) {
    assert.equal(call.arguments.length, 2);
    assert.equal(call.arguments[1]!.getText(parsed), 'signal');
  }
});

test('real workspace/controller births and worker identity are registered before respecting preparation cancellation', () => {
  const activation = between(source('./run-execution.ts'), 'async function activateWorker(', 'function checkpointRetirement(');
  for (const record of ['recordWorkerPreparationGeneration', 'recordWorkspaceGenerationPreactivated',
    'recordWorkerPreparationController', 'recordWorkerPreactivated']) {
    assert(activation.includes(`${record}(driver, artifacts, owner,`), `${record} must retain the original result-registration catalog`);
    assert(!activation.includes(`${record}(driver, reads, owner,`), `${record} must not turn a real birth into an unrecorded cancellation`);
  }
  const birth = activation.indexOf('workspaceBirth = await materialization.birth();');
  const registration = activation.indexOf('recordWorkerPreparationGeneration(driver, artifacts, owner,');
  const copyingStop = activation.indexOf('signal.throwIfAborted();', registration);
  assert(birth >= 0 && registration > birth && copyingStop > registration, 'physical birth must be bound before the existing copy cancellation boundary');
  const readonlyPair = activation.indexOf('recordWorkspaceGenerationPreactivated(driver, artifacts, owner,');
  const readonlyStop = activation.indexOf('signal.throwIfAborted();', readonlyPair);
  assert(readonlyPair > registration && readonlyStop > readonlyPair, 'the original readonly registration pair must complete before its existing stop check');
});

test('Agent and Delivery construction scope every opening read without retaining their constructor signal for later settlement', () => {
  const agent = source('./reducers/agent.ts'), tool = source('./reducers/tool.ts');
  assert.match(agent, /\}, reobserve, signal\)/u);
  const opening = between(tool, 'export async function loadToolContinuation(', 'const cut = async');
  assert.match(opening, /openingSignal\?: AbortSignal/u);
  assert.match(opening, /const openingReads = openingSignal \? artifacts\.withReadSignal\(openingSignal\) : artifacts/u);
  assert.doesNotMatch(opening, /readCanonicalArtifact(?:<[^>]+>)?\(artifacts|artifacts\.readBytes/u);
  const retained = between(tool, '// Recovery independently reproduces committed decisions', 'const controlAuthority =');
  assert.doesNotMatch(retained, /readCanonicalArtifact(?:<[^>]+>)?\(artifacts|await verifyGrant\(item\.grantRef\)|verifyApproval\(item\.decisionRef\)/u);
  const authority = source('./run-authority.ts');
  const construction = between(authority, '  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);', '  const assertAuthority =');
  assert.match(construction, /const openingReads = signal \? artifacts\.withReadSignal\(signal\) : artifacts/u);
  assert.doesNotMatch(construction, /readRecoveryClosure\(driver, artifacts|readCanonicalArtifact(?:<[^>]+>)?\(artifacts|validateVerifierRunAdmission\(driver, artifacts/u);
  const retainedAuthority = between(authority, '  const assertAuthority =', '  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);\n  return');
  assert.match(retainedAuthority, /readSignal\?: AbortSignal/u);
  assert.doesNotMatch(retainedAuthority, /openingReads|\bsignal\?\./u);
  assert.match(source('./run-continuation.ts'), /authority\.controlAuthority\.assertAuthority\(signal\)/u);
});

test('retained input-history construction uses the opening lifetime while future input operations keep their original catalog', () => {
  const input = source('./reducers/input.ts'), tool = source('./reducers/tool.ts');
  assert.match(input, /openingSignal\?: AbortSignal/u);
  assert.match(input, /const openingReads = openingSignal \? artifacts\.withReadSignal\(openingSignal\) : artifacts/u);
  const operations = '  return {\n    async plan(';
  const opening = between(input, '  if (driver.prepare("SELECT 1 FROM items', operations);
  assert.match(opening, /authority\.assertAuthority\(openingSignal\)/u);
  assert.match(opening, /recover\(openingReads\)/u);
  assert.match(opening, /verifyReply\(reply\.itemRef, recovered, openingReads\)/u);
  const retained = input.slice(input.indexOf(operations));
  assert.doesNotMatch(retained, /openingReads|openingSignal/u);
  assert.match(retained, /await authority\.assertAuthority\(\)/u);
  assert.match(tool, /loadInputContinuation\(driver, artifacts, owner, \{ \.\.\.controlAuthority, contracts \}, reobserve, openingSignal\)/u);
});

// Execute the exact existing verifier item-decoding expression, with its
// actual decoder/join helper and real CAS. No Store, Run or owner is created.
function verifierItems(): (selected: { items: Array<{ itemSeq: number; payloadRef: string }> }, reads: ArtifactCatalog) => Promise<unknown> {
  const body = between(source('./verifier-execution.ts'), 'prepareVerifier: stateOperation(', 'failVerifierPreparation: stateOperation(');
  const parsed = ts.createSourceFile('verifier-preparation-data.ts', body, ts.ScriptTarget.Latest, true);
  const expressions: ts.Expression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'existingItems' && node.initializer)
      expressions.push(node.initializer);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(expressions.length, 1);
  const output = ts.transpileModule(`return (async () => ${expressions[0]!.getText(parsed)})();`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const decode = new Function('selected', 'reads', 'readCanonicalArtifact', 'joinResourceOperations', output);
  return (selected, reads) => decode(selected, reads, readCanonicalArtifact, joinResourceOperations) as Promise<unknown>;
}

for (const fault of ['cancel', 'retirement'] as const) test(`verifier cancellation joins both real CAS decoder returns before exposing ${fault === 'cancel' ? 'the original refusal' : 'close uncertainty'}`, async t => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-verifier-read-join-'));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root), catalog = new ArtifactCatalog(cas);
  const first = await catalog.publishCanonical({ diagnosticOnly: true, ordinal: 1 }, 'cliq-read-join-data-v1');
  const second = await catalog.publishCanonical({ diagnosticOnly: true, ordinal: 2 }, 'cliq-read-join-data-v1');
  const selected = { items: [{ itemSeq: 1, payloadRef: first.ref }, { itemSeq: 2, payloadRef: second.ref }] };
  const owner = new AbortController(), reason = new Error('the original verifier preparation read was revoked');
  const closeFailure = new Error('the real second root closed but its retirement report is uncertain');
  const call = new AsyncLocalStorage<string>(), active = new Set<object>(), open = fs.open, read = cas.read.bind(cas);
  const gates = [0, 1].map(() => { let release!: () => void; return { promise: new Promise<void>(resolve => { release = resolve; }), release }; });
  let enter!: () => void, returned = 0, outerJoined = false, actualRootCloseFailure = false;
  const entered = new Promise<void>(resolve => { enter = resolve; });
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args), ref = call.getStore(); active.add(handle);
    const close = handle.close.bind(handle);
    t.mock.method(handle, 'close', async () => {
      await close(); assert.equal(active.delete(handle), true);
      if (fault === 'retirement' && ref === second.ref && args[0] === root) {
        actualRootCloseFailure = true; throw closeFailure;
      }
    });
    return handle;
  });
  t.mock.method(cas, 'read', (...args: Parameters<typeof cas.read>) => call.run(args[0], async () => {
    let bytes: Buffer | undefined, failed: { error: unknown } | undefined;
    try { bytes = await read(...args); } catch (error) { failed = { error }; }
    if (++returned === 2) enter();
    await gates[args[0] === first.ref ? 0 : 1]!.promise;
    if (failed) throw failed.error;
    return bytes!;
  }));
  const decode = verifierItems();
  const work = decode(selected, catalog.withReadSignal(owner.signal));
  void work.then(() => { outerJoined = true; }, () => { outerJoined = true; });
  try {
    await Promise.race([entered, work.then(() => { throw new Error('the real CAS return gates were bypassed'); })]);
    assert.equal(active.size, 0, 'both real CAS operations close before either return gate is released');
    owner.abort(reason); gates[0]!.release(); await setImmediate();
    assert.equal(outerJoined, false, 'the first refusal must not detach its still-pending decoder sibling');
    gates[1]!.release();
    await assert.rejects(work, error => fault === 'cancel' ? error === reason : error instanceof ResourceRetirementError && error.cause === closeFailure);
    assert.equal(actualRootCloseFailure, fault === 'retirement'); assert.equal(active.size, 0);
  } finally { gates.forEach(gate => gate.release()); await Promise.allSettled([work]); t.mock.restoreAll(); }
});

test('cancelling a scoped canonical decoder cannot accept an already-joined CAS return or revoke the separate settlement catalog', async t => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-agent-read-return-'));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root), catalog = new ArtifactCatalog(cas);
  const original = { diagnosticOnly: true, value: 'retained bytes, not Run authority' };
  const { ref } = await catalog.publishCanonical(original, 'cliq-read-cancellation-data-v1');
  let enter!: () => void, release!: () => void;
  const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const open = fs.open, read = cas.read.bind(cas), active = new Set<object>();
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args); active.add(handle);
    const close = handle.close.bind(handle);
    t.mock.method(handle, 'close', async () => { await close(); assert.equal(active.delete(handle), true); });
    return handle;
  });
  t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => {
    const bytes = await read(...args);
    assert.equal(active.size, 0, 'the return gate is after the original real descriptor joins');
    enter(); await gate; return bytes;
  });
  const abort = new AbortController(), reason = new Error('the actual readonly owner was revoked');
  const reading = readCanonicalArtifact(catalog.withReadSignal(abort.signal), ref);
  let joined = false; void reading.then(() => { joined = true; }, () => { joined = true; });
  try {
    await entered; abort.abort(reason);
    assert.equal(joined, false, 'cancellation alone is not a join receipt');
    release(); await assert.rejects(reading, error => error === reason);
    assert.equal(active.size, 0);
    assert.deepEqual(await readCanonicalArtifact(catalog, ref), original, 'the independent original settlement reader remains usable');
  } finally { release(); await Promise.allSettled([reading]); t.mock.restoreAll(); }
});
