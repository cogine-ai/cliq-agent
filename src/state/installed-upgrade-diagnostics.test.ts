import assert from 'node:assert/strict';
import { test } from 'node:test';
import { INSTALLED_RUNTIME_UPGRADE_PHASES, installedRuntimeUpgradeFailureMarker, readInstalledRuntimeUpgradeFailureMarker } from './installed-upgrade-diagnostics.js';

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
    ERR_DLOPEN_FAILED: 'DLOPEN_FAILED' })) examples.push([Object.assign(privateFields(Error()), { code: native }), code]);
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
