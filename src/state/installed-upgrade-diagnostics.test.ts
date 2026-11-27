import assert from 'node:assert/strict';
import { test } from 'node:test';
import { INSTALLED_RUNTIME_UPGRADE_PHASES, installedUpgradeRecoveryPhase, installedRuntimeUpgradeFailureMarker, readInstalledRuntimeUpgradeFailureMarker } from './installed-upgrade-diagnostics.js';

test('upgrade diagnostics emit only fixed phases and codes, with no exception or caller property execution', () => {
  const secret = 'dedicated-diagnostic-secret-never-emit';
  for (const phase of INSTALLED_RUNTIME_UPGRADE_PHASES) {
    const marker = installedRuntimeUpgradeFailureMarker(phase, { code: 'ARTIFACT_MISMATCH', message: secret, path: secret });
    assert.equal(marker, `CLIQ_INSTALLED_UPGRADE_FAILURE_V1:${phase}:ARTIFACT_MISMATCH\n`); assert(!marker.includes(secret));
  }
  let calls = 0;
  const accessor = Object.defineProperty({}, 'code', { get() { calls++; throw new Error(secret); } });
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { calls++; throw new Error(secret); } });
  for (const error of [accessor, proxy, secret, null, { code: secret }])
    assert.equal(installedRuntimeUpgradeFailureMarker(secret, error), 'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:unknown:unclassified\n');
  assert.equal(calls, 0);
});

test('only one exact bounded source marker can be forwarded after scanning original stderr', () => {
  const marker = installedRuntimeUpgradeFailureMarker('stage_owner_history', { code: 'RECOVERY_REQUIRED' });
  const input = Buffer.from('untrusted child error text\n' + marker + 'other error text\n');
  const copied = readInstalledRuntimeUpgradeFailureMarker(input);
  assert.deepEqual(copied, Buffer.from(marker)); input.fill(0); assert.deepEqual(copied, Buffer.from(marker));
  for (const bytes of [Buffer.from(marker + marker), Buffer.from(marker.replace('RECOVERY_REQUIRED', 'foreign')),
    Buffer.from('prefix-' + marker), Buffer.from(marker.replace('stage_owner_history', 'foreign')), Buffer.alloc(2 * 1024 * 1024 + 1),
    new Proxy(Buffer.from(marker), {})]) assert.equal(readInstalledRuntimeUpgradeFailureMarker(bytes), undefined);
});

test('fixed native manager statuses and error classes round-trip without reading remote exception text', async () => {
  // Pure error/data projections only. These objects are not native observations,
  // process death, a D-Bus reply, a joined owner or upgrade qualification.
  const { ResourceRetirementError } = await import('./errors.js');
  const statuses = {
    platform_timeout: 'NATIVE_PLATFORM_TIMEOUT', platform_cancelled: 'NATIVE_PLATFORM_CANCELLED',
    platform_busy: 'NATIVE_PLATFORM_BUSY', invalid_platform_request: 'NATIVE_PLATFORM_INVALID_REQUEST',
    platform_worker_unavailable: 'NATIVE_PLATFORM_WORKER_UNAVAILABLE', platform_main_thread_required: 'NATIVE_PLATFORM_MAIN_THREAD_REQUIRED',
    platform_user_unavailable: 'NATIVE_PLATFORM_USER_UNAVAILABLE', platform_bus_unavailable: 'NATIVE_PLATFORM_BUS_UNAVAILABLE',
    platform_bus_identity: 'NATIVE_PLATFORM_BUS_IDENTITY', platform_bus_changed: 'NATIVE_PLATFORM_BUS_CHANGED',
    platform_service_identity: 'NATIVE_PLATFORM_SERVICE_IDENTITY', platform_service_changed: 'NATIVE_PLATFORM_SERVICE_CHANGED',
    platform_shape_mismatch: 'NATIVE_PLATFORM_SHAPE_MISMATCH', platform_observation_changed: 'NATIVE_PLATFORM_OBSERVATION_CHANGED',
    platform_inventory_bound: 'NATIVE_PLATFORM_INVENTORY_BOUND', platform_store_unavailable: 'NATIVE_PLATFORM_STORE_UNAVAILABLE',
    manager_profile_unsupported: 'NATIVE_MANAGER_PROFILE_UNSUPPORTED', manager_profile_bound: 'NATIVE_MANAGER_PROFILE_BOUND',
    process_identity_unavailable: 'NATIVE_PROCESS_IDENTITY_UNAVAILABLE'
  };
  let reads = 0;
  const privateFields = (error: Error) => {
    for (const key of ['message', 'stack', 'cause', 'name', 'path']) Object.defineProperty(error, key, {
      configurable: true, get() { reads++; throw Error('private-fixture-secret'); }
    });
    return error;
  };
  const examples: Array<[Error, string]> = Object.entries(statuses).map(([platformCode, code]) =>
    [Object.assign(privateFields(Error()), { code: 'ERR_CLIQ_CREDENTIAL_PLATFORM', platformCode }), code]);
  for (const [native, code] of Object.entries({ ERR_CLIQ_RESOURCE_RETIREMENT: 'NATIVE_RESOURCE_RETIREMENT',
    ERR_CLIQ_CREDENTIAL_SCOPE: 'NATIVE_CREDENTIAL_SCOPE_REFUSED', ERR_CLIQ_CREDENTIAL_BUSY: 'NATIVE_CREDENTIAL_BUSY',
    ERR_DLOPEN_FAILED: 'DLOPEN_FAILED', ERR_CLIQ_STATE_OWNER_NATIVE: 'NATIVE_STATE_OWNER_REFUSED',
    EPIPE: 'PIPE_CLOSED', EBADF: 'BAD_DESCRIPTOR' })) examples.push([Object.assign(privateFields(Error()), { code: native }), code]);
  for (const [error, code] of [[new TypeError(), 'TYPE_ERROR'], [new SyntaxError(), 'SYNTAX_ERROR'],
    [new RangeError(), 'RANGE_ERROR'], [new AggregateError([]), 'AGGREGATE_ERROR'], [Error(), 'ERROR'],
    [new ResourceRetirementError('private-fixture-secret', undefined), 'RECOVERY_REQUIRED']] as const)
    examples.push([privateFields(error), code]);
  const { readFile } = await import('node:fs/promises');
  const c = await readFile(new URL('../../native/linux/credential-platform.c', import.meta.url), 'utf8');
  // Literal fixed-label provenance, not C execution or native authority.
  for (const status of Object.keys(statuses)) assert(c.includes(`"${status}"`));
  for (const phase of INSTALLED_RUNTIME_UPGRADE_PHASES) for (const [error, code] of examples) {
    const marker = installedRuntimeUpgradeFailureMarker(phase, error);
    assert.equal(marker, `CLIQ_INSTALLED_UPGRADE_FAILURE_V1:${phase}:${code}\n`);
    assert(Buffer.byteLength(marker) <= 129); assert(!marker.includes('private-fixture-secret'));
    assert.deepEqual(readInstalledRuntimeUpgradeFailureMarker(Buffer.from(marker)), Buffer.from(marker));
  }
  assert.equal(reads, 0);
});

test('unknown or accessor native statuses stay fixed and structural objects cannot select native classifications', () => {
  let reads = 0;
  const error = Object.assign(Error('private-fixture-secret'), { code: 'ERR_CLIQ_CREDENTIAL_PLATFORM' });
  Object.defineProperty(error, 'platformCode', { get() { reads++; throw Error('private'); } });
  assert.equal(installedRuntimeUpgradeFailureMarker('stop_supervisor_request', error),
    'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:stop_supervisor_request:NATIVE_PLATFORM_REFUSED\n');
  for (const value of ['private-fixture-secret', null, true, {}, new Proxy({}, {})]) {
    const raw = Object.assign(Error('private-fixture-secret'), { code: 'ERR_CLIQ_CREDENTIAL_PLATFORM', platformCode: value });
    assert.equal(installedRuntimeUpgradeFailureMarker('stop_keeper_request', raw),
      'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:stop_keeper_request:NATIVE_PLATFORM_REFUSED\n');
  }
  for (const raw of [{ code: 'ERR_CLIQ_CREDENTIAL_PLATFORM', platformCode: 'platform_timeout' },
    { code: 'NATIVE_PLATFORM_TIMEOUT' }, { code: 'ERR_DLOPEN_FAILED' }])
    assert.equal(installedRuntimeUpgradeFailureMarker('stop_original', raw),
      'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:stop_original:unclassified\n');
  assert.equal(reads, 0);
  const marker = installedRuntimeUpgradeFailureMarker('stop_keeper_decode', new TypeError('private-fixture-secret'));
  for (const bytes of [Buffer.from(marker + marker), Buffer.from(marker.replace('TYPE_ERROR', 'private-fixture-secret')),
    Buffer.alloc(2 * 1024 * 1024 + 1), new Proxy(Buffer.from(marker), {})])
    assert.equal(readInstalledRuntimeUpgradeFailureMarker(bytes), undefined);
});

test('stop subphases follow only the original operations and preserve exact Stop2/death/cancellation ownership', async () => {
  // Static wiring guard only; real installed upgrade remains the unchanged
  // signed Linux old/new journey, not a fabricated native data-positive.
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('./installed-runtime.ts', import.meta.url), 'utf8');
  const start = source.indexOf('        stop(): Promise<void> {'), end = source.indexOf('        run<T>(', start);
  assert(start >= 0 && end > start); const body = source.slice(start, end);
  const operations = ["noteUpgradePhase(observePhase, 'stop_original')", "noteUpgradePhase(observePhase, 'stop_observe_original')",
    'await observeInstalledCredentialSupervisor(selected, false)', "noteUpgradePhase(observePhase, 'stop_load_platform')",
    'await verifyBytes(platformFile)', 'process.dlopen(module', "for (const role of ['supervisor', 'keeper'] as const)",
    'const started = performance.now()', "'stop_supervisor_request' : 'stop_keeper_request'", 'activeStop = platform.stopInstalledUpgradeUnit(',
    'const raw = await activeStop', "'stop_supervisor_decode' : 'stop_keeper_decode'", 'decodeInstalledUpgradeStopObservation(raw); activeStop = undefined',
    "'stop_supervisor_death' : 'stop_keeper_death'", "credential.observeProducerLifetime(process.pid, observed.uid, process.processStartToken) !== 'dead'"];
  let previous = -1;
  for (const operation of operations) { const at = body.indexOf(operation); assert(at > previous, operation); previous = at; }
  assert.equal((body.match(/performance\.now\(\) - started >= 2000/gu) ?? []).length, 2);
  assert(body.includes('await upgradeDelay(5); assertAlive();'));
  assert(body.includes("typeof activeStop.cancelAndJoin !== 'function'"));
  assert(source.includes('if (activeStop && !stopCancellation) {'));
  assert(source.includes('stopCancellation = activeStop.cancelAndJoin().catch(failedJoin)'));
  assert(source.includes('stopCancellation = Promise.reject(error).catch(failedJoin)'));
  assert(!body.includes('console.') && !body.includes('writeSync('));
});


test('the actual unsafe native error becomes a sticky-retirement type with its exact original cause', async () => {
  const { installedUpgradeRetirementFailure } = await import('./installed-upgrade-diagnostics.js');
  const { ResourceRetirementError } = await import('./errors.js');
  const raw = Object.assign(Error(), { code: 'ERR_CLIQ_RESOURCE_RETIREMENT', platformCode: 'resource_retirement' });
  let reads = 0;
  for (const key of ['message', 'stack', 'cause', 'path', 'name']) Object.defineProperty(raw, key, {
    configurable: true, get() { reads++; throw Error('private-fixture-secret'); }
  });
  const failure = installedUpgradeRetirementFailure(raw);
  assert(failure instanceof ResourceRetirementError);
  assert.equal(Object.getOwnPropertyDescriptor(failure, 'cause')!.value, raw);
  assert.equal(installedUpgradeRetirementFailure(failure), failure, 'an original retirement failure keeps its exact identity');
  assert.equal(installedRuntimeUpgradeFailureMarker('stop_supervisor_request', failure),
    'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:stop_supervisor_request:NATIVE_RESOURCE_RETIREMENT\n');
  assert.equal(reads, 0);
  const ordinary = Object.assign(Error(), { code: 'ERR_CLIQ_CREDENTIAL_PLATFORM', platformCode: 'platform_timeout' });
  assert.equal(installedUpgradeRetirementFailure(ordinary), undefined);
  for (const foreign of [{ code: 'ERR_CLIQ_RESOURCE_RETIREMENT' }, new Proxy({}, { get() { throw Error('private'); } }),
    Object.defineProperty(Error(), 'code', { get() { reads++; throw Error('private'); } })])
    assert.equal(installedUpgradeRetirementFailure(foreign), undefined);
  assert.equal(reads, 0);
});

test('unsafe stop and cancellation failures reach the original credential scope before any release decision', async () => {
  // Data/source wiring only. No manufactured NativeCredentialScope is used.
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('./installed-runtime.ts', import.meta.url), 'utf8');
  const stop = source.slice(source.indexOf('        stop(): Promise<void> {'), source.indexOf('        run<T>(', source.indexOf('        stop(): Promise<void> {')));
  assert(stop.includes('const failure = installedUpgradeRetirementFailure(error);'));
  assert(stop.includes('if (failure) { rememberRetirement(failure); throw failure; }'));
  const close = source.slice(source.indexOf('const held: HeldInstalledRuntimeUpgrade = Object.freeze('), source.indexOf('installedUpgradeStages.set(held,'));
  assert(close.includes("new ResourceRetirementError('installed upgrade native stop cancellation did not join', error)"));
  assert(close.includes('rememberRetirement(failure); throw failure;'));
  assert(close.includes('stopCancellation = activeStop.cancelAndJoin().catch(failedJoin)'));
  assert(close.includes('stopCancellation = Promise.reject(error).catch(failedJoin)'));
  const run = source.slice(source.indexOf('        run<T>(', source.indexOf('installedUpgradeStages.set(held,')), source.indexOf('        async publish(', source.indexOf('installedUpgradeStages.set(held,')));
  assert(run.indexOf('await joinResourceOperations([failed ? Promise.reject(failure) : Promise.resolve(), stopCancellation])') <
    run.indexOf('transactionActive = false; credential = undefined;'));
  assert(run.includes('} catch (error) { healthy(); throw error; }'));
  const native = await readFile(new URL('./native-owner.ts', import.meta.url), 'utf8');
  const original = native.slice(native.indexOf('export async function withHeldCredentialNativeScope'), native.indexOf('/** Private verified-installation bridge.', native.indexOf('export async function withHeldCredentialNativeScope')));
  assert(original.indexOf('if (failure instanceof ResourceRetirementError) throw failure;') < original.indexOf('try { owned.close(); }'));
});

test('conversion subphases only label original operations and preserve the complete audit and five-second commit window', async () => {
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('./runtime-upgrade.ts', import.meta.url), 'utf8');
  const operations = [
    ["'conversion_current'", 'if (installed) await installed.assertCurrent()'],
    ["'conversion_owner'", 'await stateOwnerFilesystemFromArtifacts('],
    ["'conversion_schema'", 'const source = await readCanonicalArtifact<RuntimeBundleManifest>'],
    ["'conversion_history'", 'const history = await readRetainedStateOwnerHistory(driver, reads, prior.ownerEpoch)'],
    ["'conversion_resources'", "for (const table of ['runs', 'worker_launches', 'workspace_generations', 'source_inspection_attempts'])"],
    ["'conversion_rows'", 'await readRuntimeUpgradeRetiredRows(driver, reads, resources.refs)'],
    ["'conversion_death'", 'const acquiredAt = sampleCanonicalNow(), current = await currentProcessIdentity(native, acquiredAt)'],
    ["'conversion_receipt'", 'const processObject = await reads.publishCanonical(current,'],
    ["'conversion_selection'", 'if (installed) await installed.prepareSelection(receiptObject.ref)'],
    ["'conversion_acquisition'", 'const acquisitionObject = await reads.publishCanonical(acquisition,'],
    ["'conversion_commit'", 'const committed = driver.transaction(connection =>'],
    ["'conversion_publish'", 'if (installed) await installed.publishSelection(receiptObject.ref, receipt)'],
    ["'conversion_release'", 'await gracefullyReleaseStateOwner(driver, reads, contextFromStateOwner(owner, lock,']
  ];
  for (const [phase, consumer] of operations) {
    assert((INSTALLED_RUNTIME_UPGRADE_PHASES as readonly string[]).includes(phase!.slice(1, -1)), phase);
    const note = `installed?.notePhase?.(${phase})`, at = source.indexOf(note), operation = source.indexOf(consumer!);
    assert(at >= 0 && at < operation, phase); assert.equal(source.split(note).length, 2);
  }
  assert.equal(source.match(/age < 0 \|\| age > 5000/gu)?.length, 1);
  assert(source.indexOf('await readRuntimeUpgradeRetiredRows(driver, reads, resources.refs)') < source.indexOf('const acquiredAt = sampleCanonicalNow()'));
  const start = source.indexOf('const committed = driver.transaction'), end = source.indexOf('if (!committed)', start);
  for (const guard of ['history.assertUnchanged(connection)', 'versionCounter(connection,', 'lock.assertPriorProcessDead(',
    'installed?.assertCommit()', 'installed?.assertOldProcessesDead()', 'applySignedKernelSchema7To8(connection)', 'transferTimeFenceOwner('])
    assert(source.slice(start, end).includes(guard), guard);
  assert(!source.includes('console.') && !source.includes('writeSync('));
  const runtime = await readFile(new URL('./installed-runtime.ts', import.meta.url), 'utf8');
  assert(runtime.includes('notePhase: phase => noteUpgradePhase(observePhase, phase)'));
});


test('every original conversion resource boundary and complete recovery subphase has a fixed marker', async () => {
  const recovery = ['cut', 'preparation', 'spec', 'context', 'journal', 'generations', 'history',
    'history_model', 'history_items', 'history_candidate', 'history_verifier', 'history_tool', 'history_input',
    'history_broker', 'seals', 'terminal'] as const;
  const resources = ['counts', 'run_row', 'run_journal', 'run_retain', 'worker_row', 'worker_retain',
    'generation_row', 'generation_retain', 'source_row', 'source_retirement', 'source_retain', 'unsupported', 'graph'] as const;
  for (const boundary of [...resources.map(value => `conversion_resource_${value}`),
    ...recovery.map(value => `conversion_run_${value}`)]) {
    assert((INSTALLED_RUNTIME_UPGRADE_PHASES as readonly string[]).includes(boundary), boundary);
    const marker = installedRuntimeUpgradeFailureMarker(boundary, { code: 'RECOVERY_REQUIRED' });
    assert.equal(marker, `CLIQ_INSTALLED_UPGRADE_FAILURE_V1:${boundary}:RECOVERY_REQUIRED\n`);
    assert.deepEqual(readInstalledRuntimeUpgradeFailureMarker(Buffer.from(marker)), Buffer.from(marker));
  }
  for (const phase of recovery) assert.equal(installedUpgradeRecoveryPhase(phase), `conversion_run_${phase}`);
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('./runtime-upgrade.ts', import.meta.url), 'utf8');
  const recoverySource = await readFile(new URL('./recovery-closure.ts', import.meta.url), 'utf8');
  const operations = [
    ['counts', "for (const table of ['runs', 'worker_launches', 'workspace_generations', 'source_inspection_attempts'])"],
    ['run_row', 'const run = readRun(driver, id)'],
    ['run_journal', 'if (closure.journal.some('],
    ['run_retain', 'await retain(run, runTerminalRowRefs)'],
    ['worker_row', "if (launch.phase !== 'retired')"],
    ['worker_retain', 'await retain(launch, workerLaunchRowRefs)'],
    ['generation_row', 'await assertClosedUpgradeGeneration(driver, reads, run, row, retainedWorkers)'],
    ['generation_retain', 'await retain(row, workspaceGenerationRowRefs)'],
    ['source_row', 'const row = readSourceInspectionAttempt(driver,'],
    ['source_retirement', 'await readSourceInspectionRetirement(driver, reads, row,'],
    ['source_retain', 'await retain(row, sourceInspectionRowRefs)'],
    ['unsupported', "for (const table of ['local_inference_activation_cycles'"],
    ['graph', 'const resources = await publishUpgradeResourceGraph(']
  ];
  for (const [label, operation] of operations) {
    const note = `installed?.notePhase?.('conversion_resource_${label}')`;
    assert(source.indexOf(note) >= 0 && source.indexOf(note) < source.indexOf(operation!), label);
    assert(source.split(note).length >= 2, label);
  }
  assert(source.includes('readRecoveryClosure(driver, reads, id, installed && (phase => installed.notePhase?.(installedUpgradeRecoveryPhase(phase))))'));
  assert(recoverySource.indexOf("phase('cut')") < recoverySource.indexOf('const databaseCut ='));
  assert(recoverySource.indexOf("phase('preparation')") < recoverySource.indexOf('await validateWorkerPreparationHistory('));
});


test('real Store recovery retains its full cut and original refusal when the phase observer throws', async () => {
  const { createQueuedFixture, disposeFixture } = await import('./testing/fixtures.js');
  const { openSqliteDriver } = await import('./sqlite-driver.js');
  const { readRecoveryClosure } = await import('./recovery-closure.js');
  const { canonicalSha256 } = await import('../kernel/canonical.js');
  const path = await import('node:path');
  const fixture = await createQueuedFixture('upgrade-resource-phases');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, 'kernel.sqlite3'));
  try {
    const original = await readRecoveryClosure(driver, fixture.store.artifacts, fixture.runId);
    const phases: string[] = [];
    const observed = await readRecoveryClosure(driver, fixture.store.artifacts, fixture.runId, phase => {
      phases.push(installedUpgradeRecoveryPhase(phase)); throw Error('observer-only-private-text');
    });
    assert.equal(canonicalSha256(observed), canonicalSha256(original));
    assert.deepEqual(phases, ['cut', 'preparation', 'spec', 'context', 'journal', 'generations', 'history', 'seals', 'terminal']
      .map(value => `conversion_run_${value}`));
    const failed: string[] = [];
    await assert.rejects(readRecoveryClosure(driver, fixture.store.artifacts, 'absent-original-run', phase => {
      failed.push(phase); throw Error('observer-only-private-text');
    }), { code: 'NOT_FOUND' });
    assert.deepEqual(failed, ['cut']);
  } finally { driver.close(); await disposeFixture(fixture); }
});


test('upgrade output subphases and codes append closed values without changing legacy marker order', () => {
  const prior = INSTALLED_RUNTIME_UPGRADE_PHASES.indexOf('unknown');
  assert.deepEqual(INSTALLED_RUNTIME_UPGRADE_PHASES.slice(prior + 1),
    ['output_selection_open', 'output_stdio_open', 'output_write', 'output_join', 'output_selection_close']);
  for (const [raw, code] of [['ERR_CLIQ_STATE_OWNER_NATIVE', 'NATIVE_STATE_OWNER_REFUSED'], ['EPIPE', 'PIPE_CLOSED'], ['EBADF', 'BAD_DESCRIPTOR']]) {
    let accessed = 0;
    const error = Object.assign(Error(), { code: raw });
    for (const field of ['message', 'stack', 'cause', 'path', 'name']) Object.defineProperty(error, field, {
      configurable: true, get() { accessed++; throw new Error('private output bytes'); }
    });
    for (const phase of INSTALLED_RUNTIME_UPGRADE_PHASES.slice(prior + 1)) {
      const marker = installedRuntimeUpgradeFailureMarker(phase, error);
      assert.equal(marker, `CLIQ_INSTALLED_UPGRADE_FAILURE_V1:${phase}:${code}\n`);
      assert.deepEqual(readInstalledRuntimeUpgradeFailureMarker(Buffer.from(marker)), Buffer.from(marker));
      assert(Buffer.byteLength(marker) <= 128);
    }
    assert.equal(accessed, 0);
  }
});

test('actual upgrade output diagnosis preserves the original write failure through joined cleanup and reports distinct cleanup failures', async () => {
  // Only the entry's presentation branch runs over ordinary streams/inert
  // callbacks. No upgrade, held selection, native descriptor or authority is
  // manufactured; the real installed journey remains independent.
  const { readFile } = await import('node:fs/promises'), { Script } = await import('node:vm');
  const { Writable, PassThrough } = await import('node:stream'), ts = (await import('typescript')).default;
  const { clientWriter } = await import('../client/entry.js');
  const { joinResourceOperations } = await import('./errors.js');
  const { canonicalJsonBytes, canonicalSha256 } = await import('../kernel/canonical.js');
  const source = ts.createSourceFile('installed-entry.ts', await readFile(new URL('./installed-entry.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  let branch: import('typescript').IfStatement | undefined;
  const visit = (node: import('typescript').Node) => {
    if (ts.isIfStatement(node) && node.expression.getText(source) === "mode === '--upgrade-runtime'") branch = node;
    ts.forEachChild(node, visit);
  }; visit(source); assert(branch);
  const code = branch!.getText(source).replace("const { openInstalledClientStdio } = await import('../client/stdio.js');", '')
    .replace("const { clientWriter } = await import('../client/entry.js');", '');
  for (const stage of ['success', 'selection_open', 'stdio_open', 'write', 'join', 'selection_close'] as const) {
    const primary = Object.assign(Error(), { code: 'EPIPE' }), retirement = Object.assign(Error(), { code: 'EBADF' });
    const calls: string[] = [], markers: string[] = [];
    const output = stage === 'write' ? new Writable({ write(_bytes, _encoding, callback) { callback(primary); } }) : new PassThrough();
    output.on('data', () => {});
    const selected = { async close() { calls.push('selection_close'); if (stage === 'selection_close') throw retirement; } };
    const dependencies = { mode: '--upgrade-runtime', process: { argv: ['inert', 'inert', '--upgrade-runtime', '/state', '/package'],
      stdin: new PassThrough(), stdout: output, stderr: new PassThrough(), once() {}, removeListener() {} },
      normalizeAbsolutePath: (value: string) => value, AbortController, canonicalJsonBytes, canonicalSha256, clientWriter, joinResourceOperations,
      upgradeInstalledRuntime: async () => { calls.push('upgrade_return'); return { targetRuntimeBundleRef: 'a'.repeat(64) }; },
      runtime: { async openSelected() { calls.push('selection_open'); if (stage === 'selection_open') throw primary; return selected; } },
      openInstalledClientStdio: async () => { calls.push('stdio_open'); if (stage === 'stdio_open') throw primary;
        return { io: { output }, async close() { calls.push('stdio_close'); output.destroy(); if (stage === 'join') throw retirement; } }; },
      writeSync: (_fd: number, marker: string) => { markers.push(marker); }, installedRuntimeUpgradeFailureMarker };
    const names = Object.keys(dependencies), compiled = ts.transpileModule(`return async function() { ${code} };`,
      { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const invoke = new Script(`(function(${names.join(',')}) { ${compiled} })`).runInThisContext()(...Object.values(dependencies)) as () => Promise<void>;
    if (stage === 'success') { await invoke(); assert.deepEqual(markers, []); }
    else {
      await assert.rejects(invoke(), error => error === (['join', 'selection_close'].includes(stage) ? retirement : primary));
      assert.deepEqual(markers, [`CLIQ_INSTALLED_UPGRADE_FAILURE_V1:output_${stage}:${['join', 'selection_close'].includes(stage) ? 'BAD_DESCRIPTOR' : 'PIPE_CLOSED'}\n`]);
    }
    if (!['selection_open', 'stdio_open'].includes(stage)) assert(calls.includes('stdio_close'));
    if (stage !== 'selection_open') assert.equal(calls.at(-1), 'selection_close');
    output.destroy();
  }
});
