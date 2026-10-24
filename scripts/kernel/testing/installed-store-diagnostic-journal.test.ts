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

test('one fixed original Stop phase is inert immutable retained data, not a completed task', async () => {
  const { readInstalledStoreStopPhaseJournal } = await import('./installed-store-diagnostic-journal.js');
  const observed = readInstalledStoreStopPhaseJournal(journal(['CLIQ_STORE_STOP_PHASE_V1:drive_agent']), sender);
  assert.deepEqual(observed, { phase: 'drive_agent' }, 'only the original fixed phase is retained');
  assert.equal(Object.isFrozen(observed), true, 'the retained phase is immutable');
  assert.equal(Object.hasOwn(observed!, 'qualified'), false, 'a phase cannot establish qualification');
  assert.equal(Object.hasOwn(observed!, 'originalServerJoined'), false, 'a phase cannot establish original join');
  assert.equal(readInstalledStoreStopPhaseJournal(journal(), sender), undefined, 'a summary is not a Stop phase marker');
  assert.equal(readInstalledStoreStopPhaseJournal('', sender), undefined, 'an empty valid window has no marker');
  assert.equal(readInstalledStoreStopPhaseJournal(journal(['unrelated CLIQ_STORE_STOP_PHASE mention']), sender), undefined,
    'unrelated prose is not a marker');
  assert.deepEqual(readInstalledStoreStopPhaseJournal(journal(['CLIQ_STORE_STOP_PHASE_V1:drive_agent']),
    Object.assign(Object.create(null), sender)), { phase: 'drive_agent' }, 'plain null-prototype identities remain valid');
});

test('Stop phase markers reject malformed versions, fields, phases, duplicate rows and non-ASCII bytes', async () => {
  const { readInstalledStoreStopPhaseJournal } = await import('./installed-store-diagnostic-journal.js');
  const marker = 'CLIQ_STORE_STOP_PHASE_V1:drive_agent';
  const malformed = [
    'CLIQ_STORE_STOP_PHASE', 'CLIQ_STORE_STOP_PHASE_V', 'CLIQ_STORE_STOP_PHASE_V1', 'CLIQ_STORE_STOP_PHASE_V1:',
    'CLIQ_STORE_STOP_PHASE_V2:drive_agent', 'CLIQ_STORE_STOP_PHASE_V01:drive_agent',
    'CLIQ_STORE_STOP_PHASE_V1_extra:drive_agent', 'CLIQ_STORE_STOP_PHASEV1:drive_agent',
    'CLIQ_STORE_STOP_PHASE_V1:1:drive_agent', 'CLIQ_STORE_STOP_PHASE_V1:drive_agent:1',
    'CLIQ_STORE_STOP_PHASE_V1:unavailable', 'CLIQ_STORE_STOP_PHASE_V1:unknown',
    'CLIQ_STORE_STOP_PHASE_V1:drive_agent ', 'CLIQ_STORE_STOP_PHASE_V1: drive_agent',
    marker + ':extra', marker + '\n', marker + '\r', marker + '\t', marker + '\u0000', marker + '\u007f', marker + 'é',
    'CLIQ_STORE_STOP_PHASE_V1:' + 'x'.repeat(73)
  ];
  for (const row of malformed)
    assert.throws(() => readInstalledStoreStopPhaseJournal(journal([row]), sender), 'a malformed Stop marker must be rejected');
  for (const messages of [[marker, marker], [marker, 'CLIQ_STORE_STOP_PHASE_V1:scheduled'],
    [marker, 'CLIQ_STORE_STOP_PHASE_V2:drive_agent'], [marker, 'CLIQ_STORE_STOP_PHASE_V1']])
    assert.throws(() => readInstalledStoreStopPhaseJournal(journal(messages), sender), 'one original Stop observation permits only one marker');
});

test('Stop observations use only closed scheduler phases, including preparation details, never submit stages', async () => {
  const { readInstalledStoreStopPhaseJournal, readInstalledStoreDiagnosticJournal,
    readInstalledPublicationStageJournal } = await import('./installed-store-diagnostic-journal.js');
  const preparation = ['publication_prepare_read', 'publication_prepare_grant', 'publication_prepare_cut',
    'publication_prepare_physical', 'publication_prepare_admit'];
  for (const phase of ['scheduled', 'drive_retirement_quarantine_closure', 'result_recovery_history_candidate', ...preparation]) {
    assert.deepEqual(readInstalledStoreStopPhaseJournal(journal([`CLIQ_STORE_STOP_PHASE_V1:${phase}`]), sender), { phase },
      'a current closed scheduler phase is retained');
    const summary = readInstalledStoreDiagnosticJournal(journal(['CLIQ_STORE_DIAG_V1:begin:0:1',
      `CLIQ_STORE_DIAG_V1:scheduler:drive:${phase}:0:other:none:-`, 'CLIQ_STORE_DIAG_V1:stop:1:0:0:0:0',
      `CLIQ_STORE_DIAG_V1:phase:${phase}:1`, 'CLIQ_STORE_DIAG_V1:end']), sender)!;
    assert.equal(summary.firstSchedulerFailure!.phase, phase, 'the original summary still accepts the same scheduler phase');
    assert.deepEqual(summary.stop.phases, { [phase]: 1 }, 'the original summary preserves phase multiplicity');
  }
  for (const phase of preparation)
    assert.throws(() => readInstalledPublicationStageJournal(journal([`CLIQ_PUBLICATION_STAGE_V1:1:${phase}`]), sender),
      'preparation details do not become live publication arrivals');
  for (const stage of ['submit_request', 'submit_preflight_authority', 'submit_source_capture',
    'submit_assembly', 'submit_final_admission', 'submit_postcommit_load']) {
    assert.throws(() => readInstalledStoreStopPhaseJournal(journal([`CLIQ_STORE_STOP_PHASE_V1:${stage}`]), sender),
      'submit stages are not scheduler phases');
    const messages = lines.map(row => row.replace('apply:postcommit_load:', `apply:${stage}:`));
    assert.equal(readInstalledStoreDiagnosticJournal(journal(messages), sender)!.firstApplyFailure!.stage, stage,
      'submit stages remain in the original admission summary only');
    assert.throws(() => readInstalledStoreDiagnosticJournal(journal(lines.map(row => row.replace('phase:drive_agent:', `phase:${stage}:`))), sender),
      'submit stages cannot become summary scheduler phases');
    assert.throws(() => readInstalledPublicationStageJournal(journal([`CLIQ_PUBLICATION_STAGE_V1:1:${stage}`]), sender),
      'submit stages cannot become live publication arrivals');
  }
});

test('Stop decoding preserves the original whole-window sender, transport, invocation and fixed row/byte guards', async () => {
  const { readInstalledStoreStopPhaseJournal } = await import('./installed-store-diagnostic-journal.js');
  const marker = 'CLIQ_STORE_STOP_PHASE_V1:drive_agent';
  const original = { _UID: '1000', _PID: '2000', _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE: marker };
  for (const mutation of [{ _UID: '1001' }, { _PID: '2001' }, { _TRANSPORT: 'syslog' },
    { _SYSTEMD_INVOCATION_ID: 'b'.repeat(32) }, { _UID: 1000 }, { _PID: 2000 },
    { _SYSTEMD_INVOCATION_ID: undefined }, { MESSAGE: null }, { MESSAGE: [marker] }]) {
    const foreign = JSON.stringify({ ...original, ...mutation });
    assert.throws(() => readInstalledStoreStopPhaseJournal(foreign, sender), 'a marker requires the original complete sender binding');
    assert.throws(() => readInstalledStoreStopPhaseJournal(journal([marker]) + foreign + '\n', sender),
      'the complete window, not only selected marker rows, is bound to the original sender');
  }
  for (const text of [JSON.stringify(original).slice(0, -1), 'null', '[]',
    JSON.stringify(original).replace('"_UID":"1000"', '"_UID":"1000","_UID":"1000"'),
    journal([marker, ...Array(80).fill('unrelated diagnostic text')]), ' '.repeat(256 * 1024 + 1)])
    assert.throws(() => readInstalledStoreStopPhaseJournal(text, sender), 'malformed or over-budget whole windows must be refused');
  assert.deepEqual(readInstalledStoreStopPhaseJournal(journal([marker, ...Array(79).fill('unrelated diagnostic text')]), sender),
    { phase: 'drive_agent' }, 'the original eighty-row boundary remains accepted');
  const exactBytes = journal([marker]);
  assert.deepEqual(readInstalledStoreStopPhaseJournal(exactBytes + ' '.repeat(256 * 1024 - Buffer.byteLength(exactBytes)), sender),
    { phase: 'drive_agent' }, 'the original whole-window byte boundary remains accepted');
});

test('Stop decoding rejects hostile expected identities without invoking accessors, proxy traps or coercions', async () => {
  const { readInstalledStoreStopPhaseJournal } = await import('./installed-store-diagnostic-journal.js');
  let traps = 0; const bad = () => { traps++; throw new Error('must not be observed'); };
  const revoked = Proxy.revocable(sender, {}); revoked.revoke();
  for (const expected of [null, [], Object.create(sender), Object.defineProperty({ ...sender }, 'uid', { get: bad }),
    Object.defineProperty({ ...sender }, 'pid', { get: bad }), Object.defineProperty({ ...sender }, 'invocationId', { get: bad }),
    Object.defineProperty({ ...sender }, 'uid', { value: 1000, enumerable: false }),
    { ...sender, extra: 1 }, { ...sender, [Symbol('extra')]: 1 }, new Proxy(sender, { ownKeys: bad, getPrototypeOf: bad, get: bad }),
    revoked.proxy, { ...sender, uid: 0 }, { ...sender, uid: 1.5 }, { ...sender, uid: Number.MAX_SAFE_INTEGER + 1 },
    { ...sender, pid: 0 }, { ...sender, pid: -1 }, { ...sender, pid: 1.5 }, { ...sender, uid: { valueOf: bad } },
    { ...sender, invocationId: sender.invocationId + '\n' }, { ...sender, invocationId: 'A'.repeat(32) },
    { ...sender, invocationId: { toString: bad } }])
    assert.throws(() => readInstalledStoreStopPhaseJournal(journal(['CLIQ_STORE_STOP_PHASE_V1:drive_agent']), expected as never),
      'expected identity must be exact inert plain data');
  for (const text of [null, 1, Symbol('text'), { toString: bad }, new Proxy({}, { get: bad })])
    assert.throws(() => readInstalledStoreStopPhaseJournal(text as never, sender), 'journal text must not be coerced');
  assert.equal(traps, 0, 'decoding must not invoke hostile input behavior');
});

test('the independent Stop marker cannot change original summary or publication reader acceptance', async () => {
  const { readInstalledStoreStopPhaseJournal, readInstalledStoreDiagnosticJournal,
    readInstalledPublicationStageJournal } = await import('./installed-store-diagnostic-journal.js');
  const marker = 'CLIQ_STORE_STOP_PHASE_V1:publication_prepare_read';
  const arrivals = ['CLIQ_PUBLICATION_STAGE_V1:1:publication_select', 'CLIQ_PUBLICATION_STAGE_V1:2:publication_prepare'];
  const complete = journal([...arrivals, marker, ...lines]);
  assert.deepEqual(readInstalledStoreDiagnosticJournal(complete, sender), readInstalledStoreDiagnosticJournal(journal(), sender),
    'the original complete summary is unaffected by an independent Stop marker');
  assert.deepEqual(readInstalledPublicationStageJournal(complete, sender), { phases: ['publication_select', 'publication_prepare'] },
    'the original publication arrivals are unaffected by an independent Stop marker');
  assert.deepEqual(readInstalledStoreStopPhaseJournal(complete, sender), { phase: 'publication_prepare_read' },
    'the independent Stop observation remains available beside both old protocols');
  const malformedMarker = 'CLIQ_STORE_STOP_PHASE_V1:drive_agent:private';
  assert.deepEqual(readInstalledStoreDiagnosticJournal(journal([...lines, malformedMarker]), sender),
    readInstalledStoreDiagnosticJournal(journal(), sender), 'the old summary does not acquire new Stop protocol validation');
  assert.deepEqual(readInstalledPublicationStageJournal(journal([...arrivals, malformedMarker]), sender),
    { phases: ['publication_select', 'publication_prepare'] }, 'the old arrival reader does not acquire new Stop protocol validation');
  assert.throws(() => readInstalledStoreDiagnosticJournal(journal([...lines.slice(0, -1), marker]), sender),
    'a Stop marker cannot complete a truncated original summary');
  assert.throws(() => readInstalledPublicationStageJournal(journal([arrivals[0]!, 'CLIQ_PUBLICATION_STAGE_V1:3:publication_prepare', marker]), sender),
    'a Stop marker cannot repair an original publication ordinal gap');
});

test('publication arrival markers retain only distinct original first arrivals, not a completion or joined result', async () => {
  const { readInstalledPublicationStageJournal, readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const phases = ['publication_select', 'publication_worker_activate', 'publication_roots_open', 'publication_prepare'];
  const messages = phases.map((phase, index) => `CLIQ_PUBLICATION_STAGE_V1:${index + 1}:${phase}`);
  const observed = readInstalledPublicationStageJournal(journal(messages), sender)!;
  assert.deepEqual(observed, { phases }); assert(Object.isFrozen(observed) && Object.isFrozen(observed.phases));
  assert.equal(Object.hasOwn(observed, 'qualified'), false); assert.equal(Object.hasOwn(observed, 'originalServerJoined'), false);
  assert.equal(readInstalledStoreDiagnosticJournal(journal(messages), sender), undefined, 'arrival markers cannot manufacture an exit summary');
  assert.deepEqual(readInstalledStoreDiagnosticJournal(journal([...messages, ...lines]), sender), readInstalledStoreDiagnosticJournal(journal(), sender));
  assert.deepEqual(readInstalledPublicationStageJournal(journal(['CLIQ_PUBLICATION_STAGE_V1:1:publication_settlement']), sender),
    { phases: ['publication_settlement'] }, 'first-seen order is not a claimed complete execution order');
  assert.equal(readInstalledPublicationStageJournal(journal(), sender), undefined);
});

test('publication markers refuse gaps, duplication, unknown fields, excess rows and a foreign original process', async () => {
  const { readInstalledPublicationStageJournal } = await import('./installed-store-diagnostic-journal.js');
  const marker = 'CLIQ_PUBLICATION_STAGE_V1:1:publication_select';
  for (const messages of [[marker + ':private'], [marker.replace(':1:', ':01:')], [marker.replace(':1:', ':0:')],
    [marker.replace(':1:', ':2:')], [marker.replace('publication_select', 'private')], [marker + '\u0000'],
    [marker, marker.replace(':1:', ':2:')], [marker, 'CLIQ_PUBLICATION_STAGE_V1:3:publication_prepare'],
    Array.from({ length: 7 }, (_, index) => marker.replace(':1:', `:${index + 1}:`))])
    assert.throws(() => readInstalledPublicationStageJournal(journal(messages), sender));
  for (const mutation of [{ _UID: '1001' }, { _PID: '2001' }, { _TRANSPORT: 'syslog' }, { _SYSTEMD_INVOCATION_ID: 'b'.repeat(32) }]) {
    const record = { _UID: '1000', _PID: '2000', _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId,
      MESSAGE: marker, ...mutation };
    assert.throws(() => readInstalledPublicationStageJournal(JSON.stringify(record), sender));
  }
  let accessed = false;
  const getter = Object.defineProperty({ ...sender }, 'pid', { enumerable: true, get() { accessed = true; throw 0; } });
  assert.throws(() => readInstalledPublicationStageJournal(journal([marker]), getter));
  assert.throws(() => readInstalledPublicationStageJournal(journal([marker]), new Proxy(sender, { ownKeys() { accessed = true; throw 0; } })));
  assert.equal(accessed, false);
});

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
