// Source wiring only. The real Linux timeout-retirement-failure campaign
// independently verifies the unchanged wait and retained live StateOwner.
// This test creates no task, native receipt, Run or recovery authority.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Script } from 'node:vm';
import { test } from 'node:test';
import ts from 'typescript';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

test('close and committed stop cancel tool release reads while retaining the original claimed producer', async () => {
  // Execute the original shutdown decisions with inert callbacks only. Real
  // SQLite/CAS tests own read joins; Linux independently owns native retirement.
  const parsed = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'),
    ts.ScriptTarget.Latest, true);
  const bodies: ts.Block[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'beginClose' && node.body) bodies.push(node.body);
    if (ts.isPropertyAssignment(node) && node.name.getText(parsed) === 'requestStop' &&
        ts.isArrowFunction(node.initializer) && ts.isBlock(node.initializer.body)) bodies.push(node.initializer.body);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(bodies.length, 2);
  for (const body of bodies) {
    const statements = body.statements;
    const native = statements.findIndex(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(declaration =>
      declaration.name.getText(parsed) === 'joins' || declaration.name.getText(parsed) === 'joined'));
    assert(native > 0);
    const operationAbort = new AbortController(), toolReleaseReadAbort = new AbortController();
    const context = { KernelStorageError, driver: {}, owner: {}, runId: 'inert-run', revoking: undefined, closed: false,
      preflightAbort: new AbortController(), verifierReleaseReadAbort: undefined, toolReleaseReadAbort,
      publicationProjectionAbort: undefined, operationAbort, operationPhase: 'claimed', pending: {}, receivedCompletion: undefined,
      worker: {}, activeWorker: {}, closingCompletion: undefined, stopJoin: undefined, probe: undefined,
      mcpStatusProbe: undefined, mcpStatusRecovery: undefined, publicationReconciliationTask: undefined,
      continuation: { operation: 'agent' }, readRun: () => ({ stopIntentRef: 'inert-committed-intent' }),
      assertActiveStateOwner() {}, revokePublications() {}, stop: undefined as undefined | (() => void) };
    new Script(ts.transpileModule(`globalThis.stop = () => { ${statements.slice(0, native).map(node => node.getText(parsed)).join('\n')} };`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText).runInNewContext(context);
    context.stop!();
    assert(toolReleaseReadAbort.signal.aborted, 'the release-only read must cancel before native joins');
    assert.equal(operationAbort.signal.aborted, false, 'the claimed producer must retain custody of any real result');
  }
  const releases: ts.CallExpression[] = [];
  const collect = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'claimed.release' &&
        node.arguments[1]?.getText(parsed) === 'releaseReads.signal') releases.push(node);
    ts.forEachChild(node, collect);
  };
  collect(parsed); assert.equal(releases.length, 2, 'both verifier and builtin release bind their separately cancellable reads');
});

test('checkpoint retirement checks original owned state before revocation without reopening unrelated history', async () => {
  // Source wiring and inert values only. The real SQL/CAS identity regression
  // and installed Linux journey independently own their respective proofs.
  const parsed = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'),
    ts.ScriptTarget.Latest, true);
  let declaration: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'checkpointRetirement') declaration = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(declaration);
  for (const cancelled of [false, true]) {
    const events: string[] = [], cancellation = new Error('original retirement cancelled'), reachedRevocation = new Error('original native boundary reached');
    const launch = { launchId: 'original-launch', phase: 'activated', leaseEpoch: 1, workspaceGenerationRef: 'original-generation',
      workerIdentityDigest: 'original-worker', processContainmentRef: 'original-containment' };
    const original = { authority: { generationRef: launch.workspaceGenerationRef }, recipe: {}, reserved: {},
      activated: { launch }, processContainmentRef: launch.processContainmentRef, closure: {} };
    const context = { activeWorker: original, worker: {}, generation: {}, ownedLaunchId: launch.launchId,
      driver: {}, artifacts: {}, owner: {}, runId: 'original-run', KernelStorageError,
      identityHash: () => 'original-quiesce', assertActiveStateOwner() {},
      async readRecoveryClosure() { events.push('unrelated-history'); throw new Error('unrelated history must not delay native retirement'); },
      readOwnedWorkerRetirementCut(_driver: unknown, _owner: unknown, activated: unknown, closure: unknown) {
        assert.equal(activated, original.activated); assert.equal(closure, original.closure); events.push('owned-state');
        return { run: { activeWorkerLaunchId: launch.launchId, leaseEpoch: launch.leaseEpoch },
          workspaceGenerations: [{ generationRef: launch.workspaceGenerationRef }], workerLaunches: [launch] };
      },
      beginGenerationRevocation() { events.push('native-revocation'); throw reachedRevocation; },
      current: original, signal: { throwIfAborted() { if (cancelled) throw cancellation; } },
      retire: undefined as undefined | (() => Promise<unknown>) };
    new Script(ts.transpileModule(`${declaration.getText(parsed)}\nglobalThis.retire = checkpointRetirement(current, 'checkpoint', signal);`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText).runInNewContext(context);
    await assert.rejects(context.retire!(), error => error === (cancelled ? cancellation : reachedRevocation));
    assert.deepEqual(events, cancelled ? ['owned-state'] : ['owned-state', 'native-revocation']);
  }
});

test('a pending tool-selection read keeps its original live worker lease through the read', async () => {
  // Inert renewal-policy values only. This does not create a clock, worker,
  // StateOwner, lease or native proof. Linux owns the physical qualification.
  const parsed = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'),
    ts.ScriptTarget.Latest, true);
  let renewal: ts.Block | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isPropertyAssignment(node) && node.name.getText(parsed) === 'renewCurrentWorkerLease' &&
        ts.isArrowFunction(node.initializer) && ts.isBlock(node.initializer.body)) renewal = node.initializer.body;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(renewal);
  for (const phase of ['reading', 'preparing', 'received']) for (const held of [false, true]) {
    let now = 0, expiresAt = 35, calls = 0;
    const context = { pending: {}, receivedCompletion: phase === 'received' ? {} : undefined,
      operationPhase: phase, publicationLeaseReads: undefined, agentLeaseReads: held ? {} : undefined,
      dependencyOwner: undefined, verifierReleased: false, toolReleased: false,
      renewOwnedWorkerLease() { calls++; if (now >= expiresAt) return 'expired'; expiresAt = now + 60; return 'renewed'; },
      renew: undefined as undefined | (() => string) };
    new Script(ts.transpileModule(`globalThis.renew = () => ${renewal.getText(parsed)};`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText).runInNewContext(context);
    now = 20;
    const result = context.renew!();
    now = 45;
    if (phase === 'reading' && held) {
      assert.equal(result, 'renewed'); assert.equal(calls, 1);
      assert(expiresAt > now, 'a pure selection read must not consume its original worker lease');
      now = expiresAt;
      assert.equal(context.renew!(), 'expired', 'the original renewal still refuses expiry');
      context.agentLeaseReads = undefined;
      assert.equal(context.renew!(), 'inactive', 'a closed producer cannot retain read renewal');
    } else { assert.equal(result, 'inactive'); assert.equal(calls, 0); }
  }
});

test('failed worker producers close lease reads before recovery while original retryable results retain them', async () => {
  // Execute the original lifecycle decisions only. The callbacks below carry
  // no Run, lease, StateOwner, native worker, result or recovery authority.
  const parsed = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'),
    ts.ScriptTarget.Latest, true);
  let operation: ts.FunctionDeclaration | undefined, renewal: ts.Block | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'ownOperation') operation = node;
    if (ts.isPropertyAssignment(node) && node.name.getText(parsed) === 'renewCurrentWorkerLease' &&
        ts.isArrowFunction(node.initializer) && ts.isBlock(node.initializer.body)) renewal = node.initializer.body;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(operation?.body && renewal);
  const rejection = operation.body.statements[2];
  assert(rejection && ts.isVariableStatement(rejection));
  const initializer = rejection.declarationList.declarations[0]?.initializer;
  assert(initializer && ts.isCallExpression(initializer) && ts.isPropertyAccessExpression(initializer.expression));
  const caught = initializer.expression.expression;
  assert(ts.isCallExpression(caught));
  const callback = caught.arguments[0]; assert(callback && ts.isArrowFunction(callback) && ts.isBlock(callback.body));
  const recovery = callback.body.statements.findIndex(ts.isTryStatement); assert(recovery >= 0);
  const beforeRecovery = callback.body.statements.slice(0, recovery).map(node => node.getText(parsed)).join('\n');
  for (const role of ['publication', 'agent']) for (const retryable of [false, true]) {
    let renewals = 0, closes = 0;
    const original = new Error('inert original refusal'), activeWorker = {}, leaseReads = { close() { closes++; } };
    const context = { ResourceRetirementError, operationFailure: undefined, retainedCompletion: false,
      receivedCompletion: retryable ? { kind: role === 'publication' ? 'publication' : 'tool', worker: undefined, activeWorker } : undefined,
      worker: undefined, activeWorker, publicationLeaseReads: role === 'publication' ? leaseReads : undefined,
      agentLeaseReads: role === 'agent' ? leaseReads : undefined,
      operationPhase: retryable ? 'claimed' : 'preparing', pending: {}, cleanupFailure: undefined,
      dependencyOwner: undefined, verifierReleased: false, toolReleased: false,
      isJoinedCasPublicationFailure: () => retryable, isRolledBackSqliteTransactionFailure: () => false,
      isPublicationStopRevisionConflict: () => false, driver: {},
      renewOwnedWorkerLease() { renewals++; return 'renewed'; },
      reject: undefined as undefined | ((error: unknown) => Promise<void>), renew: undefined as undefined | (() => string) };
    new Script(ts.transpileModule(`globalThis.reject = async error => { ${beforeRecovery} };\n` +
      `globalThis.renew = () => ${renewal.getText(parsed)};`,
    { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText).runInNewContext(context);
    assert.equal(context.renew!(), role === 'publication' ? 'renewed' : 'inactive');
    if (retryable) await assert.rejects(context.reject!(original), error => error === original);
    else await context.reject!(original);
    assert.equal(closes, retryable ? 0 : 1);
    assert.equal(context.publicationLeaseReads, role === 'publication' && retryable ? leaseReads : undefined);
    assert.equal(context.agentLeaseReads, role === 'agent' && retryable ? leaseReads : undefined);
    assert.equal(context.renew!(), role === 'publication' && retryable ? 'renewed' : 'inactive');
    assert.equal(renewals, role === 'publication' ? retryable ? 2 : 1 : 0);
  }
});

test('shutdown cancels the original failure recovery read before using the checked owned-worker fence', async () => {
  // Original failure-branch ordering only, with inert callbacks. No worker,
  // native death, Run or StateOwner evidence is manufactured here.
  const parsed = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  let selected: ts.IfStatement | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.expression.getText(parsed) === 'ownedLaunchId !== undefined && run.activeWorkerLaunchId === ownedLaunchId') {
      assert.equal(selected, undefined); selected = node;
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(selected);
  for (const mode of ['shutdown', 'ordinary_failure', 'unjoined_failure', 'replaced_worker'] as const) {
    const events: string[] = [], preflightAbort = new AbortController(), reads = {};
    const cancelled = new Error('inert shutdown'), failure = mode === 'unjoined_failure'
      ? new ResourceRetirementError('inert original read did not join', new Error('inert close failure')) : new Error('inert ordinary failure');
    const original = { activated: {}, closure: {} };
    const context = { closed: false, activeWorker: original, driver: {}, artifacts: {}, owner: {}, runId: 'inert-run',
      run: { revision: 1 }, preflightAbort, preflightReads: reads, isClosing: () => context.closed,
      beginWorkerRecovery: async (_driver: unknown, catalog: unknown) => {
        events.push('recover'); assert.equal(catalog, reads, 'failure recovery requires the shutdown-cancellable read catalog');
        if (mode !== 'ordinary_failure') { context.closed = true; preflightAbort.abort(cancelled); }
        if (mode === 'replaced_worker') context.activeWorker = { activated: {}, closure: {} };
        events.push('read_joined'); throw mode === 'shutdown' || mode === 'replaced_worker' ? cancelled : failure;
      }, fenceOwnedWorkerOnShutdown: async (_driver: unknown, _catalog: unknown, _owner: unknown, activated: unknown, closure: unknown) => {
        assert.equal(activated, original.activated); assert.equal(closure, original.closure); events.push('fence');
      }, recover: undefined as undefined | (() => Promise<void>) };
    new Script(ts.transpileModule(`globalThis.recover = async () => ${selected.thenStatement.getText(parsed)};`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText).runInNewContext(context);
    if (mode === 'shutdown') await context.recover!();
    else await assert.rejects(context.recover!(), error => error === (mode === 'replaced_worker' ? cancelled : failure));
    assert.deepEqual(events, ['recover', 'read_joined', ...(mode === 'shutdown' ? ['fence'] : [])]);
  }
  const store = await readFile(new URL('./store.ts', import.meta.url), 'utf8');
  assert(store.includes('await beginWorkerRecovery(this.driver, this.artifacts.withReadSignal(readAbort.signal), this.owner,'));
});

test('worker probe closure preserves a completed result but cannot advance through retained cleanup uncertainty', async () => {
  const source = await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  async function closeProbe(');
  const end = source.indexOf('  async function closePublicationProbe(', start);
  assert(start >= 0 && end > start);
  const body = source.slice(start, end);
  const joined = body.indexOf('const receipt = await retained.task.cancelAndJoin();');
  const resultWins = body.indexOf('if (current.waitingOnRef !== retained.run.waitingOnRef)', joined);
  const completed = body.indexOf('if (shutdown) return current;', resultWins);
  const uncertain = body.indexOf('if (cleanupFailure !== undefined) throw cleanupFailure;', completed);
  const persist = body.indexOf('const result = await closeWorkerRecoveryProbe(', completed);
  assert(joined >= 0 && resultWins > joined && completed > resultWins && uncertain > completed && persist > uncertain,
    'a genuine result wins first; otherwise existing cleanup uncertainty must refuse before durable probe closure');
  assert.match(body, /if \(error instanceof ResourceRetirementError\) cleanupFailure \?\?= error;/u,
    'only resource retirement uncertainty becomes sticky; joined publication failures remain retryable');
  assert.match(body, /if \(retained\.closure === closingProbe\) retained\.closure = undefined;/u,
    'a failed persistence keeps the original task and permits its ordinary joined receipt retry');
  assert(!/cleanupFailure\s*=(?!=)/u.test(body), 'probe retries cannot erase the original cleanup failure');
});

test('result preparation shares the retained read lifetime without changing raw completion catalogs', async () => {
  const store = ts.createSourceFile('store.ts', await readFile(new URL('./store.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const agent = ts.createSourceFile('agent.ts', await readFile(new URL('./reducers/agent.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const execution = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const matches = <T extends ts.Node>(root: ts.Node, predicate: (node: ts.Node) => node is T): T[] => {
    const found: T[] = [];
    const visit = (node: ts.Node) => { if (predicate(node)) found.push(node); ts.forEachChild(node, visit); };
    visit(root); return found;
  };
  const call = (root: ts.Node, name: string) => {
    const found = matches(root, (node): node is ts.CallExpression => ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name);
    assert.equal(found.length, 1); return found[0]!;
  };
  const retained = matches(store, (node): node is ts.MethodDeclaration => ts.isMethodDeclaration(node) && node.name.getText(store) === 'retainInstalledAgent');
  assert.equal(retained.length, 1);
  const loading = call(retained[0]!, 'loadAgentRun');
  assert.equal(loading.arguments[1]!.getText(store), 'this.artifacts');
  assert.equal(loading.arguments[8]?.getText(store), 'readerSignal');
  assert.match(retained[0]!.getText(store), /const readerSignal = AbortSignal\.any\(\[signal, readAbort\.signal\]\);/u);
  const result = call(agent, 'loadRunResult');
  assert.equal(result.arguments[1]!.getText(agent), 'artifacts');
  assert.equal(result.arguments[5]?.getText(agent), 'resultPreparationSignal');
  for (const name of ['loadToolContinuation', 'loadRunContinuation', 'loadFinalCandidate']) {
    const original = call(agent, name);
    assert.equal(original.arguments[1]!.getText(agent), 'artifacts');
    assert(!original.arguments.some(value => value.getText(agent).includes('resultPreparationSignal')));
  }
  const physical = call(execution, 'loadAgentRun');
  assert.equal(physical.arguments[1]!.getText(execution), 'artifacts');
  assert.equal(physical.arguments.length, 7, 'the original physical result owner keeps its independently joined raw catalog');
});


test('final admission diagnoses only the actual held callback and awaited durable result before the original scope joins', async () => {
  const source = ts.createSourceFile('store.ts', await readFile(new URL('./store.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const admissions: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'admission' && node.initializer &&
        ts.isCallExpression(node.initializer) && node.initializer.expression.getText(source) === 'withCredentialAuthorityLock') admissions.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(admissions.length, 1);
  const call = admissions[0]!.initializer as ts.CallExpression, callback = call.arguments[1]!;
  assert(ts.isArrowFunction(callback) && ts.isBlock(callback.body));
  const body = callback.body, text = body.getText(source);
  assert.equal(body.statements[0]!.getText(source), "diagnosis?.stage('submit_final_admission_scope_held');");
  const durable = body.statements.find((node): node is ts.VariableStatement => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(declaration => declaration.initializer && ts.isAwaitExpression(declaration.initializer) &&
      ts.isCallExpression(declaration.initializer.expression) && declaration.initializer.expression.expression.getText(source) === 'admitInstalledRun'));
  assert(durable, 'committed must follow the original awaited admission, not just creation of its Promise');
  const held = text.indexOf("diagnosis?.stage('submit_final_admission_scope_held');"), admission = text.indexOf(durable.getText(source));
  const committed = text.indexOf("diagnosis?.stage('submit_final_admission_committed');"), returned = text.indexOf('return admitted;');
  assert(held < text.indexOf('signal.throwIfAborted();') && admission > held && committed > admission && returned > committed);
  assert.match(text, /assertCurrentControlFrame\(this\.owner, identity\); token\.assertHeld\(\);/u);
  assert(!text.includes('submit_postcommit_load'), 'postcommit load remains outside the held callback and original scope join');
  const start = admissions[0]!.pos, outer = source.getText().slice(start);
  assert(outer.indexOf('const result = await admission;') < outer.indexOf("diagnosis?.stage('submit_postcommit_load');"));
});
