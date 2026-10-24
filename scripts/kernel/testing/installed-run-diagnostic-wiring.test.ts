// Source wiring only, not a StateOwner, Run, SQLite or physical qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Script } from 'node:vm';
import { transformSync } from 'esbuild';

const source = await readFile(new URL('../../../src/state/store.ts', import.meta.url), 'utf8');
const between = (start: string, end: string) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));

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
  for (const [phase, operation] of [['read', 'const cut = await readRecoveryClosure'],
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
  for (const [phase, operation] of [['publication_select', 'const selected = await readRecoveryClosure'],
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
