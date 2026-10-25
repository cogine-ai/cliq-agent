// Source wiring and inert CAS resource lifetimes only. No StateOwner, Run,
// SQLite authority, native proof or installed physical qualification is made.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { Script } from 'node:vm';
import { transformSync } from 'esbuild';
import ts from 'typescript';
import { ArtifactCatalog } from '../../../src/state/artifacts.js';
import { ContentAddressedStore } from '../../../src/state/cas.js';
import { readCanonicalArtifact } from '../../../src/state/agent-context.js';
import { ResourceRetirementError } from '../../../src/state/errors.js';

const source = await readFile(new URL('../../../src/state/store.ts', import.meta.url), 'utf8');
const between = (start: string, end: string) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));

test('terminal retirement forwards only the existing complete recovery reader phases', async () => {
  // Execute only the real inert observer, never a Store, Run or recovery cut.
  const parsed = ts.createSourceFile('store.ts', source, ts.ScriptTarget.Latest, true);
  let method: ts.MethodDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node) && node.name.getText(parsed) === 'retireInstalledTerminalRun') method = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(method?.body);
  const calls: ts.CallExpression[] = [];
  const find = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'readRecoveryClosure') calls.push(node);
    ts.forEachChild(node, find);
  };
  find(method); assert.equal(calls.length, 1);
  const call = calls[0]!, observer = call.arguments[3];
  assert(observer && ts.isArrowFunction(observer), 'the original complete reader must receive its fixed phase observer');
  assert.deepEqual(call.arguments.slice(0, 3).map(node => node.getText(parsed)),
    ['this.driver', 'this.artifacts.withReadSignal(signal)', 'runId']);
  assert(!/\bawait\b|Date\.|performance\.|setTimeout|\.message|\.cause|\.stack/u.test(observer.getText(parsed)));
  const context = { runId: 'inert-run', invoke: undefined as any };
  new Script(transformSync(`globalThis.invoke = function() { return ${observer.getText(parsed)}; };`,
    { loader: 'ts' }).code).runInNewContext(context);
  const installedRunPhases = new Map<string, string>([['inert-run', 'terminal_retirement']]);
  const observe = context.invoke.call({ installedRunPhases }) as (phase: string) => void;
  for (const phase of ['spec', 'context', 'journal', 'generations', 'history_candidate', 'seals', 'terminal']) {
    observe(phase); assert.equal(installedRunPhases.get('inert-run'), `result_recovery_${phase}`);
  }
  installedRunPhases.delete('inert-run'); observe('terminal');
  assert.equal(installedRunPhases.size, 0, 'late diagnosis cannot recreate a retired tracking entry');
  const recovery = await readFile(new URL('../../../src/state/recovery-closure.ts', import.meta.url), 'utf8');
  assert.match(recovery, /const phase = \(value: RecoveryClosurePhase\) => \{ try \{ onPhase\?\.\(value\); \} catch \{/u);
  assert(method.getText(parsed).indexOf('await this.ownInstalledAdmission') < method.getText(parsed).indexOf('const opening ='),
    'full recovery still completes before any original execution owner can close');
});

const assemblyStages = ['submit_assembly_native', 'submit_assembly_source', 'submit_assembly_platform',
  'submit_assembly_material', 'submit_assembly_publish', 'submit_assembly_verifier', 'submit_assembly_policy',
  'submit_assembly_final_check'] as const;
async function assemblyObservation() {
  const code = await readFile(new URL('../../../src/state/installed-run.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('installed-assembly-observation.ts', code, ts.ScriptTarget.Latest, true);
  let declaration: ts.FunctionDeclaration | undefined, assembly: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'reportInstalledRunAssemblyPhase') declaration = node;
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'assembleInstalledRun') assembly = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(declaration && assembly, 'only the real production observer and assembly are selected');
  const context = { invoke: undefined as any };
  new Script(transformSync(`${declaration.getText(parsed)}; globalThis.invoke = reportInstalledRunAssemblyPhase;`,
    { loader: 'ts' }).code).runInNewContext(context);
  return { code, parsed, declaration, assembly, invoke: context.invoke as (observer: unknown, phase: string) => void };
}

test('assembly fixed observations remain outside authority input and precede only the original await groups', async () => {
  const { code, declaration, assembly } = await assemblyObservation();
  assert.match(assembly.getText(), /signal\?: AbortSignal, onAssemblyPhase\?: \(phase: InstalledRunAssemblyPhase\) => void/u);
  assert(!/\bawait\b|Date\.|performance\.|setTimeout/u.test(declaration.getText()), 'observation adds no I/O, timer or clock');
  for (const [stage, operation] of [['native', 'const native = await loadInstalledWorkerNative'],
    ['source', 'await validateControlChannelClosure'], ['platform', 'const platform = await loadInstalledCredentialPlatform'],
    ['material', 'return withHeldInstalledRuntime'], ['publish', 'const sandbox = installedSandboxProfile'],
    ['verifier', 'const verifier = await prepareInstalledVerifierAssembly'], ['policy', 'const policyRef ='],
    ['final_check', 'await installed.revalidate(signal); await validateControlChannelClosure']])
    assert(assembly.getText().includes(`reportInstalledRunAssemblyPhase(onAssemblyPhase, 'submit_assembly_${stage}');\n` +
      (['native', 'publish', 'verifier', 'policy', 'final_check'].includes(stage) ? '    ' : '  ') + operation), stage);
  assert.equal((assembly.getText().match(/reportInstalledRunAssemblyPhase\(/gu) ?? []).length, assemblyStages.length + 1,
    'only the eight original boundaries and the contained verifier observer forwarding are present');
  assert.match(code, /type InstalledRunAssemblyPhase = Extract<InstalledApplyDiagnosticStage, `submit_assembly_\$\{string\}`>;/u);
  const submit = between('private async submitInstalledRunOwned(', '/** One bounded production lane,');
  assert.match(submit, /credentialBindings: authority.bindings, controlledHome \}, signal, diagnosis\?\.stage\);/u);
  assert.match(submit, /catch \(error\) \{\s*diagnosis\?\.failure\(error, this.closeRequested\);\s*throw error;/u);
});

test('the actual assembly observer contains sink errors and ignores absent observers without inspecting thrown values', async () => {
  const { invoke } = await assemblyObservation();
  let touched = 0;
  const bad = () => { touched++; throw new Error('private observer field'); };
  const rejected = Object.defineProperties({}, { message: { get: bad }, cause: { get: bad }, stack: { get: bad } });
  const phases: string[] = [];
  for (const phase of assemblyStages) {
    assert.doesNotThrow(() => invoke(undefined, phase));
    assert.doesNotThrow(() => invoke((value: string) => { phases.push(value); throw rejected; }, phase));
    assert.doesNotThrow(() => invoke(Object.defineProperty({}, 'call', { get: bad }), phase));
    assert.doesNotThrow(() => invoke(new Proxy({}, { get: bad, ownKeys: bad, getPrototypeOf: bad }), phase));
  }
  assert.deepEqual(phases, [...assemblyStages]); assert.equal(touched, 0);
});

const verifierPreparationStages = ['submit_assembly_verifier_history', 'submit_assembly_verifier_current',
  'submit_assembly_verifier_compose', 'submit_assembly_verifier_publish'] as const;
async function verifierPreparationObservation() {
  const code = await readFile(new URL('../../../src/state/verifier-admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-admission.ts', code, ts.ScriptTarget.Latest, true);
  const functions = new Map(parsed.statements.filter(ts.isFunctionDeclaration).map(node => [node.name?.text, node]));
  const observer = functions.get('reportInstalledVerifierPreparationPhase');
  assert(observer?.body, 'the real verifier observer must contain each optional callback');
  const context = { invoke: undefined as any };
  new Script(transformSync(`${observer.getText(parsed)}; globalThis.invoke = reportInstalledVerifierPreparationPhase;`,
    { loader: 'ts' }).code).runInNewContext(context);
  return { functions, observer, invoke: context.invoke as (observer: unknown, phase: string) => void };
}

test('installed verifier preparation diagnosis follows the actual history, current image, compose and publication boundaries only', async () => {
  // Wiring only. No grant, owner, installed identity or alternate reader exists here.
  const { functions, observer } = await verifierPreparationObservation();
  assert(!/\bawait\b|Date\.|performance\.|setTimeout/u.test(observer.getText()), 'diagnosis adds no I/O, timer or clock');
  const identities = functions.get('readVerifierRequestIdentities')!.getText();
  const resolve = functions.get('resolveVerifierSpec')!.getText();
  const installed = functions.get('prepareInstalledVerifierAssembly')!.getText();
  const ordinary = functions.get('prepareVerifierSpec')!.getText();
  for (const [body, stage, operation] of [
    [identities, verifierPreparationStages[0], 'const history = await readAuthorizationHistory'],
    [identities, verifierPreparationStages[1], 'const selected = await readRetainedVerifierToolchain'],
    [resolve, verifierPreparationStages[2], 'const profile ='],
    [installed, verifierPreparationStages[3], 'const metadata = await publishVerifierAssembly']
  ]) assert(body.includes(`reportInstalledVerifierPreparationPhase(onPreparationPhase, '${stage}');\n` +
    (body === identities ? '    ' : '  ') + operation), 'a fixed phase must immediately precede its original operation');
  assert.match(resolve, /input\.requests, historical, signal, onPreparationPhase\)/u);
  assert.match(installed, /input, undefined, signal, onPreparationPhase\)/u);
  assert.match(ordinary, /input, historical, signal\)/u);
  assert(!ordinary.includes('onPreparationPhase'), 'ordinary and historical callers keep the original observer-free path');
  const { assembly } = await assemblyObservation();
  assert.match(assembly.getText(), /sandboxProfileRef \}, signal, onAssemblyPhase\s*\? phase => reportInstalledRunAssemblyPhase\(onAssemblyPhase, phase\) : undefined\)/u);
  assert.match(assembly.getText(), /identity\.principalId, request\.verifiers, undefined, signal\) : \[\]/u,
    'the earlier identity lookup does not acquire an unrelated observer');
  const input = functions.get('prepareInstalledVerifierAssembly')!.parameters.find(parameter => parameter.name.getText() === 'input')!;
  assert(!input.type!.getText().includes('Phase'), 'observation is separate from the original closed authority input');
});

test('installed verifier preparation observations contain throwing sinks without reading their private errors', async () => {
  const { invoke } = await verifierPreparationObservation();
  let accesses = 0;
  const bad = () => { accesses++; throw new Error('must not inspect a diagnostic input'); };
  const original = Object.defineProperties({}, { message: { get: bad }, stack: { get: bad }, cause: { get: bad } });
  const observed: string[] = [];
  for (const stage of verifierPreparationStages) {
    assert.doesNotThrow(() => invoke(undefined, stage));
    assert.doesNotThrow(() => invoke((phase: string) => { observed.push(phase); throw original; }, stage));
    assert.doesNotThrow(() => invoke(Object.defineProperty({}, 'call', { get: bad }), stage));
    assert.doesNotThrow(() => invoke(new Proxy({}, { get: bad, ownKeys: bad, getPrototypeOf: bad }), stage));
  }
  assert.deepEqual(observed, [...verifierPreparationStages]); assert.equal(accesses, 0);
});

for (const fault of ['cancel', 'ordinary', 'retirement'] as const)
  test(`assembly diagnosis cannot bypass the original real CAS read join or replace its ${fault}`, async t => {
    // Actual source read expression and observer only, over inert CAS data.
    // No installed selection, Session/Run/StateOwner or native proof is made.
    const { parsed, assembly, invoke } = await assemblyObservation();
    const reads: ts.CallExpression[] = [], phases: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'readCanonicalArtifact' &&
          node.arguments[1]?.getText(parsed) === 'session.workspaceIdentityRef') reads.push(node);
      if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'reportInstalledRunAssemblyPhase' &&
          node.arguments[1]?.getText(parsed) === "'submit_assembly_source'") phases.push(node);
      ts.forEachChild(node, visit);
    };
    visit(assembly); assert.equal(reads.length, 1); assert.equal(phases.length, 1);
    const context = { reportInstalledRunAssemblyPhase: invoke, readCanonicalArtifact, read: undefined as any };
    new Script(transformSync(`globalThis.read = async function(onAssemblyPhase, reads, session) {
      ${phases[0]!.getText(parsed)}; return ${reads[0]!.getText(parsed)}; };`, { loader: 'ts' }).code).runInNewContext(context);
    const directory = await mkdtemp(path.join(process.cwd(), '.cliq-assembly-diagnosis-read-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const objects = path.join(directory, 'objects'); await mkdir(objects, { mode: 0o700 });
    const cas = new ContentAddressedStore(objects), artifacts = new ArtifactCatalog(cas);
    const { ref } = await artifacts.publishCanonical({ inertOnly: true, bytes: 'x'.repeat(3 * 1024 * 1024) }, 'cliq-observer-read-data-v1');
    const owner = new AbortController(), reason = new Error('the original read was cancelled'), ordinary = new Error('the original real read failed');
    const retirement = new Error('the real root close report is uncertain'), privateFailure = Object.defineProperty({}, 'message', { get() {
      throw new Error('diagnosis must not inspect thrown observer fields');
    } });
    const active = new Set<object>(), opened = fs.open, read = cas.read.bind(cas);
    let release!: () => void, enter!: () => void, closed = 0, settled = false, originalFailure: unknown;
    const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { enter = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await opened(...args); active.add(handle);
      const close = handle.close.bind(handle), actualRead = handle.read.bind(handle);
      if (args[0] === path.join(objects, ref)) t.mock.method(handle, 'read', async (...values: Parameters<typeof handle.read>) => {
        const result = await actualRead(...values);
        if (fault === 'ordinary') throw ordinary;
        owner.abort(reason); return result;
      });
      t.mock.method(handle, 'close', async () => {
        if (args[0] === objects) { enter(); await gate; }
        await close(); assert(active.delete(handle)); closed++;
        if (fault === 'retirement' && args[0] === objects) throw retirement;
      });
      return handle;
    });
    t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => {
      try { return await read(...args); } catch (error) { originalFailure = error; throw error; }
    });
    const observed: string[] = [];
    const pending: Promise<unknown> = context.read((phase: string) => { observed.push(phase); throw privateFailure; },
      artifacts.withReadSignal(owner.signal), { workspaceIdentityRef: ref });
    void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.race([entered, pending.then(() => { throw new Error('the actual read/close gate was bypassed'); })]);
      assert.deepEqual(observed, ['submit_assembly_source']);
      assert.equal(active.size, 1); assert.equal(closed, 1); assert.equal(settled, false);
      release();
      await assert.rejects(pending, error => error === originalFailure && (fault === 'retirement'
        ? error instanceof ResourceRetirementError && error.cause === retirement : error === (fault === 'ordinary' ? ordinary : reason)));
      assert.equal(active.size, 0); assert.equal(closed, 2);
    } finally { release(); await Promise.allSettled([pending]); assert.equal(active.size, 0); t.mock.restoreAll(); }
  });

test('submit diagnosis preserves the registered producer, actual admission resolution and untouched catch error', async () => {
  // Execute the real inert catch only, never a substitute Store or authority.
  const body = between('private async submitInstalledRunOwned(', '/** One bounded production lane,');
  assert.match(body, /const diagnosis = beginInstalledSubmitDiagnostic\(\);\s*try \{/u);
  for (const [stage, operation] of [['submit_preflight_authority', 'await validateControlChannelClosure'],
    ['submit_source_capture', 'const source = await this.captureSubmittedSource'],
    ['submit_assembly', 'const assembled = await assembleInstalledRun'],
    ['submit_final_admission', 'const admission = withCredentialAuthorityLock']])
    assert(body.includes(`diagnosis?.stage('${stage}');\n      ${operation}`), stage);
  assert.match(body, /if \(\['queued', 'running', 'waiting'\]\.includes\(readRun\(this.driver, replay.run.id\).status\)\) \{\s*diagnosis\?\.stage\('submit_postcommit_load'\);\s*await this.retainInstalledAgent\(replay.run.id\);/u);
  assert.match(body, /const agentLoad = this.retainInstalledAgent\(runId, assembled.material, admission\);\s*const result = await admission;\s*diagnosis\?\.stage\('submit_postcommit_load'\);/u);
  assert.match(body, /captureSubmittedSource\(\{ request, identity \}\)/u);
  const publicBody = between('async submitInstalledRun(', 'async applyInstalledRun(');
  assert.match(publicBody, /request = immutableSnapshot\(request\);\s*return this.ownInstalledAdmission\(signal => this.submitInstalledRunOwned\(request, identity, signal\)\);/u);
  const caught = body.match(/catch \(error\) \{\s*diagnosis\?\.failure\(error, this.closeRequested\);\s*throw error;\s*\}/u)?.[0];
  assert(caught);
  const { beginInstalledSubmitDiagnostic } = await import('../../../src/state/installed-run-diagnostics.js');
  const { channel } = await import('node:diagnostics_channel');
  const diagnostic = channel('cliq.installed.run.failures.v1'), records: unknown[] = [];
  const receive = (record: unknown) => { records.push(record); }; diagnostic.subscribe(receive);
  try {
    const diagnosis = beginInstalledSubmitDiagnostic()!; diagnosis.stage('submit_final_admission');
    const original = new Error('owned original failure');
    const compiled = transformSync(`globalThis.invoke = function() { try { throw original; } ${caught} };`, { loader: 'ts' }).code;
    const context = { diagnosis, original, closeRequested: true, invoke: undefined as any };
    new Script(compiled).runInNewContext(context);
    assert.throws(() => context.invoke(), error => error === original);
    assert.deepEqual(records, [{ kind: 'apply_failure', stage: 'submit_final_admission', closing: true,
      errorClass: 'other', code: 'none', sqliteCode: null }]);
  } finally { diagnostic.unsubscribe(receive); }
});

test('publication preparation diagnosis preserves the closed authority input and every original await boundary', async () => {
  // Source wiring only: no execution, native task or authority is constructed.
  const publication = await readFile(new URL('../../../src/state/publication-invocation.ts', import.meta.url), 'utf8');
  const start = publication.indexOf('export async function preparePublicationInvocation(');
  const end = publication.indexOf('\ntype MaintenanceInput', start);
  assert(start >= 0 && end > start);
  const body = publication.slice(start, end);
  assert.match(body, /onPreparationPhase\?: \(phase: PublicationPreparationPhase\) => void/u);
  assert.match(body, /const preparationPhase = \(phase: PublicationPreparationPhase\) => \{ try \{ onPreparationPhase\?\.\(phase\); \} catch \{ \/\* Diagnosis cannot decide preparation\. \*\/ \} \};/u);
  for (const [phase, operation] of [['read', 'const { cut, prefix } = await readDeliveryPublicationClosure'],
    ['grant', 'const derived = derivePublicationGrant'], ['cut', 'await assertPublicationReadCut'],
    ['physical', 'const nativeInput = await physicalInput'], ['admit', 'const prepared = await prepareValidatedInvocation']])
    assert(body.includes(`preparationPhase('publication_prepare_${phase}');\n  ${operation}`));
  const gate = publication.slice(publication.indexOf('function closedInput('), publication.indexOf('\nasync function physicalInput('));
  assert(gate.includes("keys = ['execution', 'worker', 'workspaceRoot', 'expectedRunRevision', 'task']"));
  assert(!gate.includes('onPreparationPhase'), 'an observer is not an accepted authority field');
  assert(body.indexOf('assertDeliveryPublicationExecution(') < body.indexOf("preparationPhase('publication_prepare_read')"));
  const execution = await readFile(new URL('../../../src/state/run-execution.ts', import.meta.url), 'utf8');
  assert.match(execution, /expectedRunRevision: readRun\(driver, runId\)\.revision, signal \}, publicationPhase\);/u);
});

test('the actual preparation observer contains a throwing sink without adding awaits, clocks or error replacement', async () => {
  const publication = await readFile(new URL('../../../src/state/publication-invocation.ts', import.meta.url), 'utf8');
  const declaration = publication.match(/const preparationPhase = \(phase: PublicationPreparationPhase\) => \{[^\n]+/u)?.[0];
  assert(declaration);
  assert(!/\bawait\b|Date\.|performance\./u.test(declaration));
  const compiled = transformSync(`${declaration}\nglobalThis.invoke = preparationPhase;`, { loader: 'ts' }).code;
  const phases: string[] = [];
  const sink = { onPreparationPhase(phase: string) { phases.push(phase); throw new Error('owned diagnostic unavailable'); }, invoke: undefined as any };
  new Script(compiled).runInNewContext(sink);
  assert.doesNotThrow(() => sink.invoke('publication_prepare_grant'));
  assert.deepEqual(phases, ['publication_prepare_grant']);
});

test('worker cancellation campaign observes an unpaused original producer and requires real two-second join before successor recovery', async () => {
  // Wiring only. Only the real Linux execution can qualify this live cut.
  const campaign = await readFile(new URL('../run-linux-worker-campaign.ts', import.meta.url), 'utf8');
  const start = campaign.indexOf('async function closeActualInspection(');
  const end = campaign.indexOf('async function noOpenInvocationRecovery(', start);
  assert(start >= 0 && end > start);
  const body = campaign.slice(start, end);
  assert(!/SIGSTOP|SIGCONT|ptrace|45_000/u.test(body), 'this shutdown check must not hold a process or sleep until its deadline');
  assert.match(body, /assert\.equal\(recoverySettled, false/u);
  assert.match(body, /const closing = fixture.store.close\(\);/u);
  assert.match(body, /try \{ await bounded\(closing, 2000\); \}\s*finally \{ await closing; \}/u);
  const elapsed = body.indexOf('const closeElapsedMs = performance.now() - closingAt;');
  const reopen = body.indexOf('const store = await openStateStore(');
  const backoff = body.indexOf('await delay(Math.max(0, Date.parse(wait.probeState.nextProbeAt) - Date.now()));');
  assert(elapsed > 0 && reopen > elapsed && backoff > reopen, 'restart/backoff time cannot be mislabeled as original shutdown duration');
  assert.match(body, /assert\.equal\(wrapper.outcome, 'probe_cancelled'\)/u);
  assert.match(body, /assert\.ok\(closure.closedAt < dispatch.probeDeadlineAt/u);
  assert.match(body, /Date\.parse\(dispatch.probeDeadlineAt\) \+ 1000/u);
  assert.match(body, /assert\.deepEqual\(directChildren\(\), baseline/u);
  assert.match(body, /not installed Supervisor SIGTERM qualification/u);
});

test('publication diagnosis follows the original execution boundaries without changing work or retirement callbacks', async () => {
  const execution = await readFile(new URL('../../../src/state/run-execution.ts', import.meta.url), 'utf8');
  assert.match(execution, /onRetirementPhase\?: \(phase: RunRetirementPhase\) => void,\s*onPublicationPhase\?: \(phase: RunPublicationPhase\) => void/u);
  assert.match(execution, /const publicationPhase = \(phase: RunPublicationPhase\) => \{ try \{ onPublicationPhase\?\.\(phase\); \} catch \{ \/\* Diagnosis cannot decide publication\. \*\/ \} \};/u);
  const start = execution.indexOf('executeCurrentPublication: async value =>');
  const end = execution.indexOf('finishCurrentFinalTurn: async value =>', start);
  const body = execution.slice(start, end);
  for (const [phase, operation] of [['publication_select', 'const { cut: selected, prefix } = await readDeliveryPublicationClosure'],
    ['publication_roots_open', 'const roots = await holdPublicationRoots'],
    ['publication_prepare', 'const original = await publication.preparePublicationInvocation'],
    ['publication_dispatch', 'if (activeWorker !== current'],
    ['publication_settlement', 'const completed = publication.readOwnedPublicationCompletion']])
    assert(body.includes(`publicationPhase('${phase}');\n        ${phase === 'publication_dispatch' || phase === 'publication_settlement' ? '  ' : ''}${operation}`));
  assert.match(body, /if \(queued\) publicationPhase\('publication_worker_activate'\);\s*const current = queued \? await activateWorker\(selected, signal\) : activeWorker!;/u);
  assert.match(execution, /async function finishReceivedPublication\(\) \{\s*publicationPhase\('publication_settlement'\);/u);
  const opening = between('async loadRunExecution(input:', '/** Internal source producer,');
  assert.match(opening, /phase => \{ if \(this.installedRunPhases.has\(runId\)\) this.installedRunPhases.set\(runId, `drive_retirement_\$\{phase\}`\); \},\s*installedRunDiagnosticsSubscribed\(\) \? phase => \{\s*if \(this.installedRunPhases.has\(runId\)\) this.installedRunPhases.set\(runId, phase\);\s*noteInstalledPublicationPhase\(phase\);\s*\} : undefined/u);
});

test('received publication detail tracks only the original retirement, read, proof and settlement awaits including cached reentry', async () => {
  // Source wiring only. A phase cannot prove the awaited operation completed.
  const execution = await readFile(new URL('../../../src/state/run-execution.ts', import.meta.url), 'utf8');
  const handoff = execution.slice(execution.indexOf('await handoffOwnedPublicationResult('),
    execution.indexOf('const settlement = await preparePublicationSettlement(', execution.indexOf('await handoffOwnedPublicationResult(')));
  const order = ['await handoffOwnedPublicationResult(', "receivedCompletion = { kind: 'publication_received', finish: finishReceivedPublication };",
    "publicationPhase('publication_received_retirement');", 'await retireWorkerResources();', 'return receivedCompletion.finish();'];
  let preceding = -1;
  for (const value of order) { const next = handoff.indexOf(value); assert(next > preceding, value); preceding = next; }
  const start = execution.indexOf('async function finishReceivedPublication()');
  const received = execution.slice(start, execution.indexOf('  function ownOperation(', start));
  assert.match(received, /if \(settleReceivedPublication\) return settleReceivedPublication\(readRun\(driver, runId\)\.revision\);\s*publicationPhase\('publication_received_read'\);/u,
    'only a noncached reconstruction enters the original read phase');
  assert.match(received, /publicationPhase\('publication_received_proof'\);\s*const receivedResult = await prepareOwnedPublicationReceivedResult\(/u);
  assert.match(received, /settleReceivedPublication = async expected => \{\s*publicationPhase\('publication_received_settle'\);\s*return \(await settlement\.settle\(\{ expectedRunRevision: expected \}\)\)\.run;\s*\};/u,
    'cached and first settlement call the same original closure and await');
  assert.doesNotMatch(received, /publication_received_(?:completed|terminal|committed)|Date\.|performance\.|setTimeout/u,
    'these labels neither sample time nor pretend settlement is already a terminal transaction');
});

test('the actual fixed publication callback body cannot propagate subscriber failure or sample an absent subscriber', async () => {
  // Execute only the original inert callback declaration, not an execution
  // owner or a surrogate Run. This remains the existing source-wiring seam.
  const execution = await readFile(new URL('../../../src/state/run-execution.ts', import.meta.url), 'utf8');
  const declaration = execution.match(/const publicationPhase = \(phase: RunPublicationPhase\) => \{[^\n]+/u)?.[0];
  assert(declaration);
  const compiled = transformSync(`${declaration}\nglobalThis.invoke = publicationPhase;`, { loader: 'ts' }).code;
  const phases: string[] = [], original = new Error('subscriber unavailable');
  const throwing = { onPublicationPhase(phase: string) { phases.push(phase); throw original; }, invoke: undefined as any };
  new Script(compiled).runInNewContext(throwing);
  assert.doesNotThrow(() => throwing.invoke('publication_prepare'));
  assert.deepEqual(phases, ['publication_prepare']);
  let sampled = 0;
  const absent = { onPublicationPhase: undefined, invoke: undefined as any,
    Date: { now() { sampled++; throw 0; } }, process: { hrtime() { sampled++; throw 0; } } };
  new Script(compiled).runInNewContext(absent);
  assert.doesNotThrow(() => absent.invoke('publication_select')); assert.equal(sampled, 0);
});

test('authorization diagnosis records only existing await boundaries and rethrows the untouched original failure', async () => {
  const authorization = await readFile(new URL('../../../src/state/authorization.ts', import.meta.url), 'utf8');
  const start = authorization.indexOf('export const createAuthorization = stateOperation(');
  const end = authorization.indexOf('export const revokeAuthorization = stateOperation(', start);
  assert(start >= 0 && end > start);
  const body = authorization.slice(start, end);
  assert.match(body, /const diagnosis = beginInstalledAuthorizationDiagnostic\(\);/u);
  for (const [phase, operation] of [['current_channel', 'const channel = await validateControlChannelClosure'],
    ['replay', 'const retained = await replay()'], ['selected_toolchain', 'const selected = await readRetainedVerifierToolchain'],
    ['publish_request', 'const requestArtifact = await artifacts.publishCanonical'],
    ['publish_response', 'const response = createResponse(grant)'], ['channel_recheck', 'await validateControlChannelClosure'],
    ['transaction', 'driver.transaction(connection =>']])
    assert(body.includes(`diagnosis?.stage('${phase}');\n    ${operation}`));
  assert.match(body, /catch \(error\) \{\s*diagnosis\?\.failure\(error\);\s*throw error;/u);
  const transaction = body.slice(body.indexOf('driver.transaction(connection =>'), body.indexOf('    requireHealthyFence(outcome);'));
  assert(!transaction.includes('diagnosis'), 'no subscriber callback runs inside the original authoritative transaction');
  assert.match(transaction, /const currentOwner = assertActiveStateOwner\(connection, owner\);/u);
  assert.match(transaction, /if \(channel.channel.transport.kind === 'uds_peer'\) assertCurrentControlFrame\(owner, identity\);/u);
  assert.match(transaction, /const now = sampleCanonicalNow\(\);\s*outcome = advanceTimeFence\(connection, owner.ownerEpoch, now\);\s*if \(outcome !== 'healthy'\) return;/u);
  assert.match(transaction, /if \(now < createdAt \|\| now >= grant.expiresAt \|\| currentOwner.acquiredAt > createdAt \|\| channel.channel.openedAt > createdAt\)/u);
  assert.match(transaction, /responseRef: published.ref, committedAt: now/u);
  assert.equal((body.match(/sampleCanonicalNow\(\)/gu) ?? []).length, 2, 'preparation and actual final-transaction commit remain two distinct samples');
});

test('apply diagnostics distinguish the original admission await from postcommit loading without replacing the error', () => {
  const body = between('private async applyInstalledRunOwned(', 'private ownInstalledAdmission<');
  assert.match(body, /beginInstalledApplyDiagnostic\(\)/u);
  assert.match(body, /diagnosis\?\.stage\('admit'\);\s*const admission = admitInstalledDelivery/u);
  assert.match(body, /const result = await admission;\s*diagnosis\?\.stage\('postcommit_load'\);\s*await loaded;/u);
  assert.match(body, /catch \(error\) \{\s*diagnosis\?\.failure\(error, this.closeRequested\);\s*throw error;/u);
});

test('the driver captures its original phase before deletion and records only the original queue rejection', () => {
  const body = between('private scheduleInstalledRun(', 'private async retireInstalledTerminalRun(');
  assert.match(body, /diagnosis\?\.phase\(this.installedRunPhases.get\(runId\)\);\s*this.installedRunPhases.delete\(runId\)/u);
  assert.match(body, /this.installedRunFailures.set\(runId, error\);\s*diagnosis\?\.failure\(error, this.closeRequested\)/u);
  assert.match(body, /finally \{\s*try \{ await this.retireInstalledTerminalRun\(runId\); \}/u);
});

test('the single pre-close snapshot is subscription gated and precedes the original synchronous revocation', () => {
  const body = between('beginClose(): void {', 'const credential = installedCredentialFinalizers.get(this);');
  assert.match(body, /!this.closeRequested && this.installedRuntime && installedRunDiagnosticsSubscribed\(\)/u);
  assert(body.indexOf('noteInstalledStoreStop(') < body.indexOf('this.closeRequested = true;'), 'snapshot must precede revocation');
  assert.match(body, /phases: \[\.\.\.this.installedRunPhases.values\(\)\]/u);
});

test('only fixed qualification composition opts into Store diagnostics, including the three owned delayed campaigns', async () => {
  const builder = await readFile(new URL('./supervisor-sea-builder.ts', import.meta.url), 'utf8');
  const packaging = await readFile(new URL('./installed-supervisor-package.ts', import.meta.url), 'utf8');
  const journey = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  assert.match(builder, /input.storeFailureDiagnostics \? INSTALLED_STORE_DIAGNOSTIC_BANNER : ''/u);
  assert.match(packaging, /options.storeFailureDiagnostics \? \{ storeFailureDiagnostics: true as const \} : \{\}/u);
  assert(journey.includes('const storeFailureDiagnostics = true;'), 'each fixed qualification composition enables its trusted subscriber');
  assert.match(journey, /\.\.\.\(storeFailureDiagnostics \? \{ storeFailureDiagnostics: true as const \} : \{\}\)/u);
});

test('failure journal reads follow the original stop and actual PID absence, and publication follows writers join', async () => {
  const journey = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  assert.match(journey, /if \(options.publicationRetirementDiagnostics \|\| storeFailureDiagnostics\)/u);
  assert(journey.indexOf('if (storeFailureDiagnostics) storeFailureBinding = binding;') < journey.indexOf('try { client = await persistentClient();'),
    'the full original image and start binding must exist before any client failure');
  const start = journey.indexOf("const units = [services.supervisorUnit, services.keeperUnit] as const;");
  const stop = journey.indexOf("assert.equal(command('/usr/bin/systemctl', ['--user', 'stop', ...units]).status, 0);", start);
  const absent = journey.indexOf("await assert.rejects(lstat('/proc/' + before[index]!.MainPID), { code: 'ENOENT' });", stop);
  const reading = journey.indexOf('const summary = readInstalledStoreDiagnosticJournal(', absent);
  const joined = journey.indexOf('report.installedWritersJoined = true;', reading);
  const published = journey.indexOf('if (storeFailureObservation) report.storeFailureDiagnostics = storeFailureObservation;', joined);
  assert(stop > start && absent > stop && reading > absent && joined > reading && published > joined,
    'only the post-stop original-window read may produce an observation after all writers have joined');
  assert.match(journey, /_SYSTEMD_INVOCATION_ID=\$\{storeFailureBinding.invocationId\}/u);
});

test('arrival diagnostics can observe an abnormal original exit without satisfying any successful Stop or writer-join gate', async () => {
  const journey = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const start = journey.indexOf('let originalStopFailed = false;');
  const stop = journey.indexOf("assert.equal(command('/usr/bin/systemctl', ['--user', 'stop', ...units]).status, 0);", start);
  const originalSummary = journey.indexOf('const summary = readInstalledStoreDiagnosticJournal(', stop);
  const originalThrow = journey.indexOf('} catch (error) { originalStopFailed = true; throw error; }', originalSummary);
  const absent = journey.indexOf("await assert.rejects(lstat('/proc/' + storeFailureBinding.pid), { code: 'ENOENT' });", originalThrow);
  const read = journey.indexOf('const observation = readInstalledPublicationStageJournal(', absent);
  const joined = journey.indexOf('report.installedWritersJoined = true;', read);
  assert(start >= 0 && stop > start && originalSummary > stop && originalThrow > originalSummary && absent > originalThrow && read > absent && joined > read);
  const body = journey.slice(originalThrow, joined);
  assert.match(body, /finally \{[\s\S]*storeFailureDiagnostics && \(primary \|\| originalStopFailed\)/u);
  assert.match(body, /String\(storeFailureBinding.pid\) === before\[0\]!.MainPID &&\s*storeFailureBinding.invocationId === before\[0\]!.InvocationID/u);
  assert(body.includes("'--grep=^(CLIQ_PUBLICATION_STAGE_V1:|CLIQ_STORE_STOP_PHASE_V1:)'"));
  assert(body.includes('timeout: 5000, killSignal: \'SIGKILL\', maxBuffer: 256 * 1024'));
  assert(body.includes('scanBytes(log.stdout); scanBytes(log.stderr);'));
  assert(body.includes("source: 'actual_absent_original_supervisor_journal'"));
  assert(body.includes('originalPidObservedAbsent: true, phases: observation.phases'));
  const stopPhaseRead = body.indexOf('const stopPhase = readInstalledStoreStopPhaseJournal(text,');
  assert(stopPhaseRead > body.indexOf('const observation = readInstalledPublicationStageJournal(text,'));
  assert(body.includes('originalPidObservedAbsent: true, phase: stopPhase.phase'));
  assert.equal(body.match(/spawnSync\('\/usr\/bin\/journalctl'/gu)?.length, 1, 'both diagnostics reuse the same original bounded journal command');
  assert.equal(body.match(/scanBytes\(log\.stdout\); scanBytes\(log\.stderr\);/gu)?.length, 1);
  assert.equal(body.match(/new TextDecoder\('utf-8', \{ fatal: true \}\)\.decode\(log\.stdout\)/gu)?.length, 1);
  assert.equal(body.match(/Date\.now\(\)/gu)?.length, 2, 'the original window sample and original deadline check remain the only clocks');
  assert(!/report\.installedWritersJoined\s*=|scanner\.openStream\(/u.test(body), 'a phase is not resource-join evidence and creates no new scanner stream');
  assert(!/originalServerJoined: true|qualified: true|report\.storeFailureDiagnostics =/u.test(body), 'arrival data never upgrades exit-summary or outcome proof');
});

test('safe scanner failure diagnosis is sticky and snapshots only original counts after writers join', async () => {
  const journey = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  assert(journey.includes('firstFailureStage ??= scanStage;'), 'only the first actual scanner failure owns the fixed stage');
  assert.match(journey, /maxBytes: 512 \* 1024 \* 1024, maxStreams: 4096/u);
  const joined = journey.indexOf("assert.equal(report.installedWritersJoined, true); assert.equal(report.httpsJoined, true); assert.equal(report.daemonJoined, true);");
  const snapshot = journey.indexOf('beforeCorpus = Object.freeze({ streamsOpened: before.streamsOpened, bytesScanned: before.bytesScanned });', joined);
  const corpus = journey.indexOf("scanStage = 'corpus';", snapshot);
  const scanned = journey.indexOf('report.secretCorpus = await scanCredentialSecretCorpus(', corpus);
  const report = journey.indexOf("scanStage = 'report';", scanned);
  const originalReportScan = journey.indexOf('scanBytes(bytes); bytes.fill(0); scanner.close();', report);
  assert(joined >= 0 && snapshot > joined && corpus > snapshot && scanned > corpus && report > scanned && originalReportScan > report,
    'only original post-join counts precede the unchanged corpus and final report scans');
  assert(!journey.slice(joined, scanned).includes('await'), 'diagnosis adds no await before the original corpus operation');
  assert(journey.includes('corpusScanFailureCode = error.code;'), 'only the existing caught scanner class supplies the corpus code');
  const fallback = journey.slice(journey.indexOf('let secretScanFailure: CredentialSecretScanFailureDiagnostic | undefined;'),
    journey.indexOf('secret.fill(0); password.fill(0);'));
  assert(fallback.includes('copyCredentialSecretScanFailureDiagnostic({ diagnosticOnly: true,'), 'the fixed projection gates new fallback data');
  assert(fallback.includes("phase: 'secret_scan_or_report_failure'"), 'fallback cannot publish the original arbitrary phase');
  assert(!/\bawait\b|Date\.|performance\.|report\.phase|error\.message|error\.stack/u.test(fallback),
    'fallback adds no clock, I/O, raw phase or error text');
  assert(fallback.includes('...(secretScanFailure ? { secretScanFailure } : {})'),
    'a rejected diagnostic is omitted without replacing the original safe fallback');
});
