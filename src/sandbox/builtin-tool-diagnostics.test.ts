// Closed data/source wiring only, never a native invocation or death proof.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Script } from 'node:vm';
import ts from 'typescript';
import { KernelStorageError } from '../state/errors.js';
import { BUILTIN_EXECUTION_PHASES, isBuiltinExecutionPhase } from './builtin-tool-diagnostics.js';

const receivedPhases = ['tool_received_capture_publish', 'tool_received_checkpoint_retirement',
  'tool_received_capture_read', 'tool_received_observation_publish', 'tool_received_complete_tool'] as const;
const receivedOperations = ['capture_publish', 'checkpoint_retirement', 'capture_read', 'observation_publish', 'complete_tool'] as const;

async function receivedCompletionFixture(failAt?: string, sink: 'record' | 'throw' | 'absent' = 'record', retryConflict = false, errorOutcome = false) {
  const source = await readFile(new URL('../state/run-execution.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('run-execution.ts', source, ts.ScriptTarget.Latest, true);
  const start = source.indexOf('    executeCurrentTool: async value => {'), end = source.indexOf('    finishCurrentStop:', start);
  let phase: ts.VariableDeclaration | undefined, finish: ts.ArrowFunction | undefined, rejection: ts.ArrowFunction | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'builtinPhase') phase = node;
    if (node.getStart(parsed) >= start && node.getEnd() <= end) {
      if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'completion' && node.initializer && ts.isObjectLiteralExpression(node.initializer)) {
        const field = node.initializer.properties.find(value => ts.isPropertyAssignment(value) && value.name.getText(parsed) === 'finish');
        if (field && ts.isPropertyAssignment(field) && ts.isArrowFunction(field.initializer)) finish = field.initializer;
      }
      if (ts.isArrowFunction(node) && ts.isBlock(node.body) && node.body.statements[0]?.getText(parsed) === 'const failedBuiltinPhase = currentBuiltinPhase;') rejection = node;
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(start >= 0 && end > start && phase && finish && rejection);
  const calls: string[] = [], phases: string[] = [], failure = new Error('inert continuation rejection');
  const worker = {}, active = {}; let revision = 1, completions = 0;
  const step = async (name: string, value: unknown) => { calls.push(name); if (name === failAt) throw failure; return value; };
  // Only the actual continuation/catch and inert data stubs run here. These
  // tokens never reach a native invocation, StateOwner, SQL or CAS validator.
  const context: Record<string, any> = { isBuiltinExecutionPhase, KernelStorageError,
    onBuiltinPhase: sink === 'absent' ? undefined : (value: string) => { phases.push(value); if (sink === 'throw') throw failure; },
    activeWorker: active, current: active, worker, currentWorker: worker, ownedLaunchId: 'inert-launch',
    activated: { launch: { launchId: 'inert-launch' } }, driver: {}, owner: {}, runId: 'inert-run',
    assertActiveStateOwner() {}, capture: undefined, proof: undefined, diagnostic: undefined, observation: undefined, observationRef: undefined,
    persistCapture: () => step('capture_publish', { ref: 'inert-capture' }),
    retire: () => step('checkpoint_retirement', { postEffect: { inertOnly: true } }),
    claimed: { entry: { opId: 'inert-op', attempt: 0, requestRef: 'inert-request', target: 'inert-target', grantRef: 'inert-grant', leaseEpoch: 1 } },
    dispatchId: 'inert-dispatch', observedAt: 'inert-time', nativeModel: errorOutcome
      ? { outcome: 'error', code: 'TOOL_PROTOCOL_ERROR' } : { outcome: 'executed', content: { inertOnly: true } }, editSucceeded: false,
    artifacts: { readCanonical: () => step('capture_read', { captureDigest: 'inert-digest' }),
      publishCanonical: (value: { format: string }) => step(value.format === 'cliq-tool-output-diagnostic-v1'
        ? 'diagnostic_publish' : 'observation_publish', { ref: 'inert-publication' }) },
    digestOmitting: () => 'inert-digest', readRun: () => ({ leaseEpoch: 1, activeWorkerLaunchId: 'inert-launch', revision }),
    currentAgent: { completeTool: async () => {
      completions++;
      if (retryConflict && completions === 1) { calls.push('complete_tool'); revision++; throw new KernelStorageError('REVISION_CONFLICT', 'inert changed cut'); }
      await step('complete_tool', undefined);
    } },
    captured: { acknowledge: () => { assert.equal(context.phase(), sink === 'absent' ? undefined : 'tool_received'); return step('ack', { kind: 'inert-data-release' }); } },
    invocation: {}, claimedTool: {}, operationPhase: 'received'
  };
  const code = `let currentBuiltinPhase; const ${phase.getText(parsed)};
    globalThis.phase = () => currentBuiltinPhase;
    globalThis.completion = {finish: ${finish.getText(parsed)}};
    globalThis.originalCatch = ${rejection.getText(parsed)};`;
  new Script(ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText).runInNewContext(context);
  return { calls, phases, failure, context, run: () => context.completion.finish().catch(context.originalCatch) as Promise<unknown> };
}

test('actual received completion preserves each failed await subphase through its original outer catch', async () => {
  for (const [index, operation] of receivedOperations.entries()) {
    const fixture = await receivedCompletionFixture(operation);
    await assert.rejects(fixture.run(), error => error === fixture.failure);
    assert.equal(fixture.context.phase(), receivedPhases[index]);
    assert.equal(fixture.phases.at(-1), receivedPhases[index], 'the original catch must retain the specific failure for the scheduler');
    assert.deepEqual(fixture.calls, receivedOperations.slice(0, index + 1));
  }
});

test('the original error-outcome diagnostic publication retains its own rejection phase', async () => {
  const fixture = await receivedCompletionFixture('diagnostic_publish', 'record', false, true);
  await assert.rejects(fixture.run(), error => error === fixture.failure);
  assert.equal(fixture.context.phase(), 'tool_received_diagnostic_publish');
  assert.equal(fixture.phases.at(-1), 'tool_received_diagnostic_publish');
  assert.deepEqual(fixture.calls, ['capture_publish', 'checkpoint_retirement', 'capture_read', 'diagnostic_publish']);
});

test('a successful legacy edit completion does not report an absent capture read or error diagnostic', async () => {
  const fixture = await receivedCompletionFixture();
  fixture.context.persistCapture = undefined; fixture.context.captured = undefined;
  fixture.context.nativeModel = undefined; fixture.context.editSucceeded = true;
  await fixture.run();
  assert.deepEqual(fixture.calls, ['checkpoint_retirement', 'observation_publish', 'complete_tool']);
  assert.deepEqual(fixture.phases, ['tool_received_checkpoint_retirement', 'tool_received',
    'tool_received_observation_publish', 'tool_received', 'tool_received_complete_tool', 'tool_received']);
});

test('successful received awaits restore the original phase before ACK and preserve disabled or throwing subscribers', async () => {
  for (const errorOutcome of [false, true]) for (const sink of ['record', 'throw', 'absent'] as const) {
    const fixture = await receivedCompletionFixture(undefined, sink, false, errorOutcome);
    await fixture.run();
    const operations: string[] = [...receivedOperations], phases: string[] = [...receivedPhases];
    if (errorOutcome) { operations.splice(3, 0, 'diagnostic_publish'); phases.splice(3, 0, 'tool_received_diagnostic_publish'); }
    assert.deepEqual(fixture.calls, [...operations, 'ack']);
    assert.equal(fixture.context.phase(), sink === 'absent' ? undefined : 'tool_received');
    assert.deepEqual(fixture.phases, sink === 'absent' ? [] : phases.flatMap(phase => [phase, 'tool_received']));
  }
  const ack = await receivedCompletionFixture('ack');
  await assert.rejects(ack.run(), error => error === ack.failure);
  assert.equal(ack.context.phase(), 'tool_received', 'a later ACK failure must not inherit the successful completeTool label');
});

test('the existing changed-revision completion retry restores its phase without republishing or redispatching', async () => {
  const fixture = await receivedCompletionFixture(undefined, 'record', true);
  await fixture.run();
  assert.deepEqual(fixture.calls, [...receivedOperations, 'complete_tool', 'ack']);
  assert.deepEqual(fixture.phases.slice(-4), ['tool_received_complete_tool', 'tool_received', 'tool_received_complete_tool', 'tool_received']);
});

test('builtin phases accept only fixed original work labels without executing caller properties', () => {
  assert.equal(new Set(BUILTIN_EXECUTION_PHASES).size, BUILTIN_EXECUTION_PHASES.length);
  for (const value of BUILTIN_EXECUTION_PHASES) { assert(isBuiltinExecutionPhase(value)); assert(value.length < 64); }
  let accesses = 0;
  const bad = () => { accesses++; throw Error('private diagnostic value'); };
  for (const value of [null, true, 1, Symbol('private'), 'tool_unknown', '__proto__', new String('tool_claim'),
    Object.defineProperty({}, 'toString', { get: bad }), new Proxy({}, { get: bad, getPrototypeOf: bad, ownKeys: bad })])
    assert.equal(isBuiltinExecutionPhase(value), false);
  assert.equal(accesses, 0);
});

test('builtin stage wiring keeps the original claim, release, result and unknown settlement order', async () => {
  const execution = await readFile(new URL('../state/run-execution.ts', import.meta.url), 'utf8');
  const start = execution.indexOf('    executeCurrentTool: async value => {'), end = execution.indexOf('    finishCurrentStop:', start);
  assert(start >= 0 && end > start); const body = execution.slice(start, end);
  const ordered = [
    ["builtinPhase('tool_claim_spec')", 'const sandboxLaunchSpecRef = await publishBuiltinRecipe('],
    ["builtinPhase('tool_claim')", 'const claimed = await currentAgent.claimTool('],
    ["builtinPhase('tool_claim_data')", 'const call = await artifacts.readCanonical<'],
    ["builtinPhase('tool_claim_live')", 'const live = assertLiveDispatchState(driver, owner, runId, prepared.run.revision, activated.run.leaseEpoch,'],
    ["builtinPhase(script ? 'tool_script_closure' : 'tool_edit_closure')", 'const launchClosure = script'],
    ["builtinPhase('tool_native_parent')", 'await currentWorker.createInvocation(launchClosure, onBuiltinPhase ? builtinPhase : undefined)'],
    ["builtinPhase('tool_process_observe')", 'await invocation.observeProcess()'],
    ["builtinPhase('tool_release')", 'await claimed.release(invocation)'],
    ["builtinPhase('tool_result')", 'const result = await invocation.result()'],
    ["builtinPhase('tool_error_revoke')", 'await revokeOriginalWorker()'],
    ["builtinPhase('tool_error_history')", 'const history = readInvocationAttempt('],
    ["builtinPhase('tool_error_evidence')", "const ambiguity = await artifacts.publishCanonical("],
    ["builtinPhase('tool_error_unknown')", 'await markInvocationUnknown(']
  ];
  for (const [note, operation] of ordered) assert(body.indexOf(note!) >= 0 && body.indexOf(note!) < body.indexOf(operation!), note);
  const resultAt = body.indexOf('const result = await invocation.result()'), captureAt = body.indexOf("const captured = typeof result === 'string'"),
    observedAt = body.indexOf("builtinPhase('tool_capture')");
  assert(resultAt < captureAt && captureAt < observedAt);
  assert(!body.slice(resultAt, captureAt).includes('builtinPhase('));
  assert(body.slice(resultAt, captureAt).includes("if (onBuiltinPhase) currentBuiltinPhase = 'tool_capture'"));
  assert(body.includes('if (failedBuiltinPhase) builtinPhase(failedBuiltinPhase);\n        throw error;'));
  assert(execution.includes('if (!onBuiltinPhase || !isBuiltinExecutionPhase(phase)) return;'));
  assert(execution.includes('try { onBuiltinPhase(phase); } catch { /* Diagnosis cannot decide execution. */ }'));
  const store = await readFile(new URL('../state/store.ts', import.meta.url), 'utf8');
  assert(store.includes('} : undefined, installedRunDiagnosticsSubscribed() ? phase => {'));
  assert(store.includes('if (this.installedRunPhases.has(runId)) this.installedRunPhases.set(runId, phase);'));
});

test('native builtin stages precede original identity checks and preserve the original failure after joined inputs', async () => {
  const source = await readFile(new URL('./linux-worker.ts', import.meta.url), 'utf8');
  const start = source.indexOf('                  async createInvocation(invocationClosure, observe) {');
  const end = source.indexOf('                    assertBuiltinEditLaunchClosure(invocationClosure);', start);
  assert(start >= 0 && end > start); const body = source.slice(start, end);
  const original = ['same(invocationClosure.bundle, bundle,', 'supportedBuiltinScriptRecipe(invocationClosure)',
    'assertGuestDescription(guest.job, invocationClosure.toolchain)', 'guest.script.identity.sha256 !== invocationClosure.scriptEntry.digest',
    'canonicalSha256(invocationClosure.request) !== invocationClosure.spec.requestRef',
    'canonicalSha256(invocationClosure.target) !== invocationClosure.spec.targetRef',
    'canonicalSha256(invocationClosure.grant) !== invocationClosure.spec.operationGrantRef',
    'canonicalSha256(invocationClosure.call) !== invocationClosure.request.inputRef',
    'createdTool = native.createBuiltinTool(', 'for (const input of inputs) try { retireImage(input); }',
    'await guest.close(); guests.delete(guest); controllerGuests.delete(guest)',
    'await awaitNative(() => createdTool.pollReady() ? true : undefined, closeController, signal)',
    'actualContainment(invocationClosure, createdTool.observe())', 'await observedProcess(createdTool, launcherEntry.digest)'];
  for (const operation of original) assert(body.includes(operation), operation);
  for (const phase of BUILTIN_EXECUTION_PHASES.filter(value => value.startsWith('tool_native_') && value !== 'tool_native_parent'))
    assert(body.includes(`phase('${phase}')`), phase);
  assert(body.includes('if (primary) { if (primary.phase) phase(primary.phase); throw primary.error; }'));
  assert(body.includes('if (failedNativePhase) phase(failedNativePhase);\n                        throw error;'));
  assert(body.includes('try { observe(value); } catch { /* Inert diagnosis only. */ }'));
});
