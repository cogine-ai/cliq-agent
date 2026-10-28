// Closed data/source wiring only, never a native invocation or death proof.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { BUILTIN_EXECUTION_PHASES, isBuiltinExecutionPhase } from './builtin-tool-diagnostics.js';

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
