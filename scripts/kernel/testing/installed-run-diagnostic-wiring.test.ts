// Source wiring only, not a StateOwner, Run, SQLite or physical qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const source = await readFile(new URL('../../../src/state/store.ts', import.meta.url), 'utf8');
const between = (start: string, end: string) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));

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
  assert(body.includes("throw new KernelStorageError('REVISION_CONFLICT', 'authorization creation timestamp lost its exact control cut');"));
  assert.equal((body.match(/sampleCanonicalNow\(\)/gu) ?? []).length, 2, 'the original two real samples stay unchanged');
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
