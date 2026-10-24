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
  assert.match(drive, /loadInstalledRunMaterial\(\{ selected: this\.installedRuntime!, artifacts: reads, assemblyRef: spec\.assemblyRef, signal: readSignal \}\)/u);
  assert.match(drive, /agent\.readModelAttempt\(readSignal\)/u);
  assert.match(drive, /agent\.prepareModel\(\{ expectedRunRevision: current\.revision, leaseEpoch: current\.leaseEpoch \}, readSignal\)/u);
  const load = between(material, 'export async function loadInstalledRunMaterial(', 'export async function assembleInstalledRun(');
  assert.match(load, /const artifacts = input\.signal \? input\.artifacts\.withReadSignal\(input\.signal\) : input\.artifacts/u);
  assert.match(load, /materialFor\(installed, artifacts, assembly, input\.signal\)/u);
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
  const prepareTool = between(tool, 'prepareTool: stateOperation(', 'waitForToolApproval: stateOperation(');
  assert.match(prepareTool, /readSignal\?: AbortSignal/u);
  assert.match(prepareTool, /cut\(expectedRunRevision, reads\)/u);
  assert.doesNotMatch(prepareTool, /artifacts\.readBytes|prepareContinuationCommit\(artifacts|prepareValidatedInvocation\(driver, artifacts/u);
  const execution = source('./run-execution.ts');
  assert.match(execution, /currentAgent\.beginFinalCandidate\(\{ expectedRunRevision \}, signal\)/u);
  assert.match(execution, /continuation\.prepareVerifier\(\{ expectedRunRevision: run\.revision, leaseEpoch: run\.leaseEpoch \}, signal\)/u);
  assert.match(execution, /currentAgent\.prepareTool\(\{ expectedRunRevision: activated\.run\.revision, leaseEpoch: activated\.run\.leaseEpoch \}, signal\)/u);
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
  const opening = between(input, '  if (driver.prepare("SELECT 1 FROM items', '  return {');
  assert.match(opening, /authority\.assertAuthority\(openingSignal\)/u);
  assert.match(opening, /recover\(openingReads\)/u);
  assert.match(opening, /verifyReply\(reply\.itemRef, recovered, openingReads\)/u);
  const retained = input.slice(input.indexOf('  return {'));
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
