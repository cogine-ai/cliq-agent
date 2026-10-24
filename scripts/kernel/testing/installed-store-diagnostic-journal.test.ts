// Pure retained-data decoding only. These literals establish no process origin.
import assert from 'node:assert/strict';
import { test } from 'node:test';

const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
const lines = ['CLIQ_STORE_DIAG_V1:begin:1:1',
  'CLIQ_STORE_DIAG_V1:apply:postcommit_load:0:sqlite:ERR_SQLITE_ERROR:1',
  'CLIQ_STORE_DIAG_V1:scheduler:drive:drive_agent:0:kernel:RECOVERY_REQUIRED:-',
  'CLIQ_STORE_DIAG_V1:stop:1:0:0:1:0', 'CLIQ_STORE_DIAG_V1:phase:drive_agent:1', 'CLIQ_STORE_DIAG_V1:end'];
const journal = (messages = lines) => messages.map(MESSAGE => JSON.stringify({ _UID: '1000', _PID: '2000',
  _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n') + '\n';

test('an optional scheduler window preserves the first failure and the last actual tuple across the original stop', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const original = readInstalledStoreDiagnosticJournal(journal(), sender)!;
  assert.equal(Object.hasOwn(original, 'schedulerFailuresBeforeStop'), false);
  assert.equal(Object.hasOwn(original, 'lastSchedulerFailure'), false);
  const messages = [...lines.slice(0, 3), 'CLIQ_STORE_DIAG_V1:scheduler_window:1',
    'CLIQ_STORE_DIAG_V1:scheduler_last:drive:publication_prepare:1:other:none:-', ...lines.slice(3)];
  messages[0] = 'CLIQ_STORE_DIAG_V1:begin:1:2';
  const summary = readInstalledStoreDiagnosticJournal(journal(messages), sender)!;
  assert.deepEqual(summary, { ...original, schedulerFailures: 2, schedulerFailuresBeforeStop: 1,
    lastSchedulerFailure: { origin: 'drive', phase: 'publication_prepare', closing: true,
      errorClass: 'other', code: 'none', sqliteCode: null } });
  assert(Object.isFrozen(summary) && Object.isFrozen(summary.lastSchedulerFailure));
  const zero = readInstalledStoreDiagnosticJournal(journal(['CLIQ_STORE_DIAG_V1:begin:0:0',
    'CLIQ_STORE_DIAG_V1:scheduler_window:0', 'CLIQ_STORE_DIAG_V1:stop:1:0:0:0:0',
    'CLIQ_STORE_DIAG_V1:phase:publication_roots_open:1', 'CLIQ_STORE_DIAG_V1:end']), sender)!;
  assert.equal(zero.schedulerFailuresBeforeStop, 0); assert.equal(zero.lastSchedulerFailure, null);
});

test('a failure first observed after stop is retained as both first and last without inventing a pre-stop failure', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const summary = readInstalledStoreDiagnosticJournal(journal(['CLIQ_STORE_DIAG_V1:begin:0:1',
    'CLIQ_STORE_DIAG_V1:scheduler:drive:publication_select:1:other:none:-',
    'CLIQ_STORE_DIAG_V1:scheduler_window:0',
    'CLIQ_STORE_DIAG_V1:scheduler_last:drive:publication_select:1:other:none:-',
    'CLIQ_STORE_DIAG_V1:stop:1:0:0:0:0', 'CLIQ_STORE_DIAG_V1:phase:publication_select:1', 'CLIQ_STORE_DIAG_V1:end']), sender)!;
  assert.equal(summary.schedulerFailuresBeforeStop, 0);
  assert.deepEqual(summary.lastSchedulerFailure, summary.firstSchedulerFailure);
  assert.equal(summary.lastSchedulerFailure!.closing, true);
});

test('scheduler windows reject incomplete, reordered, foreign or contradictory fixed rows', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const window = 'CLIQ_STORE_DIAG_V1:scheduler_window:1';
  const last = 'CLIQ_STORE_DIAG_V1:scheduler_last:drive:drive_agent:0:kernel:RECOVERY_REQUIRED:-';
  const insert = (rows: string[]) => [...lines.slice(0, 3), ...rows, ...lines.slice(3)];
  const malformed = [[window], [last], [window, last, window], [window, last, last],
    ['CLIQ_STORE_DIAG_V1:scheduler_window:'], [window + ':extra', last],
    [window.replace(':1', ':2'), last], [window.replace(':1', ':-1'), last], [window.replace(':1', ':01'), last],
    [window.replace(':1', ':9007199254740992'), last],
    [window, last + ':extra'], [window, last.replace(':drive:', ':private:')],
    [window, last.replace(':drive_agent:', ':publication_unknown:')], [window, last.replace(':0:', ':2:')],
    [window, last.replace(':kernel:', ':private:')], [window, last.replace(':RECOVERY_REQUIRED:', ':private:')],
    [window, last.replace('kernel:RECOVERY_REQUIRED:-', 'kernel:ERR_SQLITE_ERROR:1')],
    [window, last.replace('kernel:RECOVERY_REQUIRED:-', 'sqlite:ERR_SQLITE_ERROR:2147483648')],
    [window, last.replace('kernel:RECOVERY_REQUIRED:-', 'kernel:RECOVERY_REQUIRED:1')],
    [window, last.replace(':drive_agent:', ':publication_prepare:')]];
  for (const rows of malformed) assert.throws(() => readInstalledStoreDiagnosticJournal(journal(insert(rows)), sender));
  for (const messages of [[window, last, ...lines], [...lines, window, last],
    [...lines.slice(0, 3), 'CLIQ_STORE_DIAG_V1:authorization:1:transaction:kernel:REVISION_CONFLICT:-', window, last, ...lines.slice(3)],
    ['CLIQ_STORE_DIAG_V1:begin:0:0', 'CLIQ_STORE_DIAG_V1:scheduler_window:0', last,
      'CLIQ_STORE_DIAG_V1:stop:0:0:0:0:0', 'CLIQ_STORE_DIAG_V1:end']])
    assert.throws(() => readInstalledStoreDiagnosticJournal(journal(messages), sender));
});

test('the maximal scheduler window and authorization summary still fits the original sixteen rows', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const names = ['drive_agent', 'drive_finalize', 'drive_material', 'drive_retirement', 'drive_verify',
    'publication_prepare', 'publication_select', 'scheduled'];
  const messages = [...lines.slice(0, 3), 'CLIQ_STORE_DIAG_V1:scheduler_window:1',
    'CLIQ_STORE_DIAG_V1:scheduler_last:drive:drive_agent:0:kernel:RECOVERY_REQUIRED:-',
    'CLIQ_STORE_DIAG_V1:authorization:1:transaction:kernel:REVISION_CONFLICT:-',
    'CLIQ_STORE_DIAG_V1:stop:8:0:0:1:0', ...names.map(phase => `CLIQ_STORE_DIAG_V1:phase:${phase}:1`), 'CLIQ_STORE_DIAG_V1:end'];
  assert.equal(messages.length, 16);
  const summary = readInstalledStoreDiagnosticJournal(journal(messages), sender)!;
  assert.equal(summary.schedulerFailuresBeforeStop, 1); assert.equal(summary.authorizationFailures, 1);
  assert.equal(Object.keys(summary.stop.phases).length, 8);
  assert.throws(() => readInstalledStoreDiagnosticJournal(journal([...messages.slice(0, -1),
    'CLIQ_STORE_DIAG_V1:phase:terminal_retirement:1', messages.at(-1)!]), sender));
});

test('an optional authorization row adds its count and first fixed failure together while old summaries stay unchanged', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const original = readInstalledStoreDiagnosticJournal(journal(), sender)!;
  assert.equal(Object.hasOwn(original, 'authorizationFailures'), false);
  assert.equal(Object.hasOwn(original, 'firstAuthorizationFailure'), false);
  const summary = readInstalledStoreDiagnosticJournal(journal([...lines.slice(0, 3),
    'CLIQ_STORE_DIAG_V1:authorization:2:transaction:kernel:REVISION_CONFLICT:-', ...lines.slice(3)]), sender)!;
  assert.deepEqual(summary, { ...original, authorizationFailures: 2,
    firstAuthorizationFailure: { stage: 'transaction', errorClass: 'kernel', code: 'REVISION_CONFLICT', sqliteCode: null } });
  assert(Object.isFrozen(summary) && Object.isFrozen(summary.firstAuthorizationFailure));
  assert.equal(Object.hasOwn(summary.firstAuthorizationFailure!, 'closing'), false);
});

test('authorization diagnostics reject half records, invalid phases, extra metadata and malformed error classifications', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const authorization = 'CLIQ_STORE_DIAG_V1:authorization:1:transaction:kernel:REVISION_CONFLICT:-';
  for (const row of [
    'CLIQ_STORE_DIAG_V1:authorization:1', 'CLIQ_STORE_DIAG_V1:authorization:transaction:kernel:REVISION_CONFLICT:-',
    authorization + ':extra', authorization + '\n', authorization.replace(':transaction:', ':unknown:'),
    authorization.replace(':1:', ':0:'), authorization.replace(':1:', ':01:'),
    authorization.replace(':1:', ':9007199254740992:'), authorization.replace(':kernel:', ':unknown:'),
    authorization.replace(':REVISION_CONFLICT:', ':private:'), authorization.replace('kernel:REVISION_CONFLICT:-', 'kernel:ERR_SQLITE_ERROR:1'),
    authorization.replace('kernel:REVISION_CONFLICT:-', 'sqlite:RECOVERY_REQUIRED:1'),
    authorization.replace('kernel:REVISION_CONFLICT:-', 'sqlite:ERR_SQLITE_ERROR:2147483648'),
    authorization.replace('kernel:REVISION_CONFLICT:-', 'kernel:REVISION_CONFLICT:1')])
    assert.throws(() => readInstalledStoreDiagnosticJournal(journal([...lines.slice(0, 3), row, ...lines.slice(3)]), sender),
      'a partial or malformed authorization diagnostic cannot produce either member of the optional pair');
  for (const messages of [[authorization, ...lines], [...lines, authorization],
    [...lines.slice(0, 3), authorization, authorization, ...lines.slice(3)]])
    assert.throws(() => readInstalledStoreDiagnosticJournal(journal(messages), sender), 'one optional row has one exact position');
});

test('one complete fixed summary decodes only its immutable error, phase and stop data', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const summary = readInstalledStoreDiagnosticJournal(journal(), sender);
  assert.deepEqual(summary, { applyFailures: 1, schedulerFailures: 1,
    firstApplyFailure: { stage: 'postcommit_load', closing: false, errorClass: 'sqlite', code: 'ERR_SQLITE_ERROR', sqliteCode: 1 },
    firstSchedulerFailure: { origin: 'drive', phase: 'drive_agent', closing: false, errorClass: 'kernel', code: 'RECOVERY_REQUIRED', sqliteCode: null },
    stop: { driverTasks: 1, agentLoads: 0, admissions: 0, retainedFailures: 1, globalFailure: false, phases: { drive_agent: 1 } } });
  assert(Object.isFrozen(summary) && Object.isFrozen(summary!.stop.phases) && Object.isFrozen(summary!.firstApplyFailure));
});

test('zero recorded failures remain null and do not claim that an active phase failed', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const actual = readInstalledStoreDiagnosticJournal(journal(['CLIQ_STORE_DIAG_V1:begin:0:0',
    'CLIQ_STORE_DIAG_V1:stop:1:0:0:0:0', 'CLIQ_STORE_DIAG_V1:phase:result_recovery_history_candidate:1', 'CLIQ_STORE_DIAG_V1:end']), sender);
  assert.equal(actual!.firstApplyFailure, null); assert.equal(actual!.firstSchedulerFailure, null);
  assert.equal(actual!.stop.retainedFailures, 0); assert.deepEqual(actual!.stop.phases, { result_recovery_history_candidate: 1 });
  assert.equal(readInstalledStoreDiagnosticJournal(journal(['unrelated diagnostic text']), sender), undefined);
});

test('missing, truncated, malformed and reordered summaries cannot become an observation', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const bad = [lines.slice(1), lines.slice(0, -1), [...lines, ...lines],
    [lines[0]!, lines[2]!, lines[1]!, ...lines.slice(3)], ['CLIQ_STORE_DIAG_V1:truncated'],
    [...lines.slice(0, -1), lines[4]!, lines.at(-1)!],
    lines.map(line => line.replace('begin:1:1', 'begin:0:1')),
    lines.map(line => line.replace('postcommit_load:0', 'postcommit_load:2')),
    lines.map(line => line.replace('postcommit_load', 'unknown')),
    lines.map(line => line.replace('sqlite:ERR_SQLITE_ERROR:1', 'kernel:ERR_SQLITE_ERROR:1')),
    lines.map(line => line.replace('sqlite:ERR_SQLITE_ERROR:1', 'sqlite:RECOVERY_REQUIRED:1')),
    lines.map(line => line.replace('sqlite:ERR_SQLITE_ERROR:1', 'sqlite:ERR_SQLITE_ERROR:2147483648')),
    lines.map(line => line.replace('begin:1:1', 'begin:01:1')),
    lines.map(line => line.replace('begin:1:1', 'begin:9007199254740992:1')),
    lines.map(line => line.replace('stop:1:0:0:1:0', 'stop:0:0:0:1:0')),
    lines.map(line => line.replace('phase:drive_agent:1', 'phase:drive_agent:1001')),
    lines.map(line => line + (line.includes(':apply:') ? ':extra' : '')),
    lines.map(line => line + (line.includes(':apply:') ? '\n' : ''))];
  for (const messages of bad) assert.throws(() => readInstalledStoreDiagnosticJournal(journal(messages), sender), 'invalid summaries must remain unavailable');
});

test('the entire window retains original sender and invocation checks and fixed byte/row bounds', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  for (const text of [journal().replace('"_PID":"2000"', '"_PID":"2001"'),
    journal().replace('"_UID":"1000"', '"_UID":"1001"'), journal().replace('"_TRANSPORT":"stdout"', '"_TRANSPORT":"journal"'),
    journal().replace(sender.invocationId, 'b'.repeat(32)), journal().replace(`"_SYSTEMD_INVOCATION_ID":"${sender.invocationId}",`, ''),
    journal().replace('"_UID":"1000"', '"_UID":"1000","_UID":"1000"'),
    journal([...Array(76).fill('unrelated diagnostic text'), ...lines]), ' '.repeat(256 * 1024 + 1)])
    assert.throws(() => readInstalledStoreDiagnosticJournal(text, sender), 'foreign, partial or over-budget windows must be refused');
});

test('expected sender accessors, proxies, hidden and extra fields are rejected without running getters', async () => {
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  let traps = 0; const bad = () => { traps++; throw 0; };
  for (const expected of [Object.defineProperty({ ...sender }, 'uid', { get: bad }),
    Object.defineProperty({ ...sender }, 'uid', { value: 1000, enumerable: false }), { ...sender, private: 'not retained' },
    { ...sender, [Symbol('private')]: 1 }, new Proxy(sender, { ownKeys: bad, getPrototypeOf: bad, get: bad }),
    { ...sender, invocationId: sender.invocationId + '\n' }])
    assert.throws(() => readInstalledStoreDiagnosticJournal(journal(), expected as never), 'invalid expected sender must not be accepted');
  assert.equal(traps, 0);
});
