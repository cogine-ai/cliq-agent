// Awaited promises, ordinary child stdio and strict data only. No Run/native
// authority, physical publication, installed Stop or Linux qualification.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { channel } from 'node:diagnostics_channel';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { INSTALLED_STORE_DIAGNOSTIC_BANNER } from './installed-store-diagnostic-banner.js';
import { readInstalledPublicationWorkJournal, readInstalledPublicationStageJournal,
  readInstalledStoreDiagnosticJournal } from './installed-store-diagnostic-journal.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';
import { INSTALLED_PUBLICATION_WORK_V2, observeInstalledPublicationWork } from '../../../src/state/installed-run-diagnostics.js';

const runId = 'u'.repeat(43), other = 'v'.repeat(43);
const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
const journal = (rows: string[]) => {
  const physical: string[] = [];
  for (let index = 0; index < rows.length; index++) {
    if (/^CLIQ_PUBLICATION_WORK_V[0-9]+:begin:/u.test(rows[index]!)) {
      const snapshot: string[] = [rows[index]!];
      while (index + 1 < rows.length && !snapshot.at(-1)!.includes(':end:')) snapshot.push(rows[++index]!);
      physical.push('CLIQ_PUBLICATION_WORK_V2:' + JSON.stringify(snapshot));
    } else physical.push(rows[index]!);
  }
  return physical.map(MESSAGE => JSON.stringify({ _UID: '1000', _PID: '2000',
    _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n');
};
const prefix = 'CLIQ_PUBLICATION_WORK_V2';
const snapshot = (boundary = 'stop', outcome = 'pending', end = '-') => [
  `${prefix}:begin:${boundary}:1`, `${prefix}:run:${runId}:100:0`,
  `${prefix}:span:${runId}:1:publication_recovery:0:${end}:${outcome}`, `${prefix}:end:${boundary}`];

test('a rejected/cancelled producer stays pending until its original join settles and preserves the exact error', async () => {
  const events: any[] = [], diagnostic = channel('cliq.installed.run.failures.v1');
  const receive = (value: unknown) => { events.push(value); }; diagnostic.subscribe(receive);
  let release!: () => void; const joined = new Promise<void>(resolve => { release = resolve; });
  const error = Object.defineProperty(Error('not observable private failure'), 'message', { get() { throw Error('no message read'); } });
  const abort = new AbortController();
  try {
    const producer = observeInstalledPublicationWork(runId, 'publication_recovery', async () => { await joined; abort.signal.throwIfAborted(); throw Error('unreachable'); });
    assert.equal(events.length, 1); assert.equal(events[0].event, 'begin');
    abort.abort(error);
    await Promise.resolve(); assert.equal(events.length, 1, 'cancellation or a phase switch/microtask is not a settled producer');
    release(); await assert.rejects(producer, cause => cause === error);
    assert.equal(events.length, 2); assert.equal(events[1].event, 'rejected');
    assert.equal(events[0].runId, runId); assert.equal(events[0].span, events[1].span);
    assert.equal(events[0].origin, events[1].origin); assert(events[1].elapsedMs >= events[0].elapsedMs);
    assert(events.every(value => Object.isFrozen(value) && Object.keys(value).length === 7));
    assert.equal(JSON.stringify(events).includes('private'), false);
    const object = {}; assert.equal(await observeInstalledPublicationWork(runId, 'publication_settlement', async () => object), object);
  } finally { release(); diagnostic.unsubscribe(receive); }
});

test('ordinary unsubscribed work does not inspect a hostile diagnostic input or change its value', async () => {
  let touched = false;
  const hostile = new Proxy({}, { get() { touched = true; throw Error('private'); }, ownKeys() { touched = true; throw Error('private'); } });
  const value = {}; assert.equal(await observeInstalledPublicationWork(hostile as never, hostile as never, async () => value), value);
  assert.equal(touched, false);
});

test('V2 strictly binds complete sender/window, Run, fixed work, monotonic endpoints and pending-to-settled progression', () => {
  const rows = [...snapshot(), ...snapshot('exit', 'rejected', '80')];
  const data = readInstalledPublicationWorkJournal(journal(rows), sender)!;
  assert.equal(data.profile, 'publication_work_v2'); assert.equal(data.snapshots[0]!.runs[0]!.spans[0]!.outcome, 'pending');
  assert.equal(data.snapshots[1]!.runs[0]!.spans[0]!.outcome, 'rejected');
  assert(Object.isFrozen(data.snapshots[0]!.runs[0]!.spans));
  assert.equal(readInstalledPublicationWorkJournal(journal(['CLIQ_PUBLICATION_STAGE_V1:1:publication_dispatch']), sender), undefined);
  assert.equal(readInstalledPublicationStageJournal(journal(rows), sender), undefined);
  const bad = [snapshot().map(row => row.replace('V2', 'V1')),
    snapshot().map(row => row.replace('publication_recovery', 'private_path')),
    snapshot().map(row => row.replace(`span:${runId}`, `span:${other}`)),
    snapshot().map(row => row.replace(':0:-:pending', ':101:-:pending')),
    snapshot().map(row => row.replace(':0:-:pending', ':0:0:pending')),
    snapshot().map(row => row.replace(':0:-:pending', ':0:-:fulfilled')),
    snapshot().map(row => row.replace(':100:0', ':100:1')),
    [...snapshot('stop', 'fulfilled', '80'), ...snapshot('exit', 'rejected', '90')],
    [...snapshot('exit'), ...snapshot('stop')], [...snapshot(), ...snapshot()],
    [...snapshot(), `${prefix}:private`], [`${prefix}:truncated`]];
  for (const rows of bad) assert.throws(() => readInstalledPublicationWorkJournal(journal(rows), sender));
  for (const binding of [{ ...sender, uid: 1001 }, { ...sender, pid: 2001 }, { ...sender, invocationId: 'b'.repeat(32) }])
    assert.throws(() => readInstalledPublicationWorkJournal(journal(rows), binding));
  assert.throws(() => readInstalledPublicationWorkJournal(journal(rows).replace('"stdout"', '"syslog"'), sender));
  assert.throws(() => readInstalledPublicationWorkJournal(journal([...rows, ...Array(80).fill('unrelated')]), sender));
});

test('actual awaited producer and bounded sink expose pending Stop then joined rejected exit without leaking the original error', async () => {
  const moduleUrl = new URL('../../../src/state/installed-run-diagnostics.ts', import.meta.url).href;
  const secret = 'private-fixture-secret-not-a-native-credential';
  const script = `import {createRequire} from 'node:module';const require=createRequire(import.meta.url);` + INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const {observeInstalledPublicationWork}=await import(${JSON.stringify(moduleUrl)});
    let release;const join=new Promise(resolve=>release=resolve);
    const producer=observeInstalledPublicationWork(${JSON.stringify(other)},'publication_received_settlement',async()=>{await join;throw Error(${JSON.stringify(secret)});});
    require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish({kind:'store_stop',driverTasks:1,agentLoads:0,admissions:1,retainedFailures:0,globalFailure:false,phases:{publication_received_settle:1}});
    process.stdin.once('data',()=>release());process.stdin.resume();process.stdout.write('ready\\n');
    try{await producer;process.exitCode=2;}catch{}
  `;
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', readyResolve!: () => void;
  const ready = new Promise<void>(resolve => { readyResolve = resolve; });
  child.stdout.on('data', bytes => { stdout += bytes.toString(); if (stdout === 'ready\n') readyResolve(); });
  child.stderr.on('data', bytes => { stderr += bytes.toString(); });
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const expiry = AbortSignal.timeout(5000), expired = new Promise<never>((_, reject) => expiry.addEventListener('abort', () => reject(Error('owned diagnostic child timeout')), { once: true }));
  try {
    await Promise.race([ready, joined.then(() => { throw Error('child exited before pending observation'); }), expired]);
    assert.equal(child.exitCode, null); assert.equal(child.signalCode, null);
    const pending = readInstalledPublicationWorkJournal(journal(stderr.trimEnd().split('\n')), sender)!;
    assert.equal(pending.snapshots.length, 1); assert.equal(pending.snapshots[0]!.boundary, 'stop');
    assert.equal(pending.snapshots[0]!.runs[0]!.spans[0]!.outcome, 'pending');
    child.stdin.end('release'); assert.deepEqual(await Promise.race([joined, expired]), { code: 0, signal: null });
    const rows = stderr.trimEnd().split('\n'), data = readInstalledPublicationWorkJournal(journal(rows), sender)!;
    assert.equal(data.snapshots.length, 2); assert.equal(data.snapshots[1]!.runs[0]!.spans[0]!.outcome, 'rejected');
    assert.equal(readInstalledStoreDiagnosticJournal(journal(rows), sender)!.schedulerFailuresBeforeStop, 0);
    assert.equal(stderr.includes(secret), false);
    const scanner = createCredentialSecretScanner([Buffer.from(secret)], { maxBytes: 8192, maxStreams: 1 });
    const stream = scanner.openStream(); stream.scan(Buffer.from(stderr)); stream.close(); assert.equal(scanner.stats().matched, false);
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await joined; }
});

test('sink retains an explicit six-span window for each of two Runs within the original whole-journal caps', () => {
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');const origin=require('node:perf_hooks').performance.now();
    for(const runId of ${JSON.stringify([runId, other])})for(let span=1;span<=20;span++)for(const event of ['begin','fulfilled'])d.publish({kind:'publication_work_v2',runId,span,work:'publication_recovery',event,origin,elapsedMs:span});
    d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{}});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
  const rows = child.stderr.trimEnd().split('\n'); assert(rows.length <= 80);
  const work = rows.filter(row => row.startsWith(prefix)); assert.equal(work.length, 2); assert(Buffer.byteLength(work.join('\n')) <= 8192);
  const data = readInstalledPublicationWorkJournal(journal(rows), sender)!;
  for (const snapshot of data.snapshots) for (const run of snapshot.runs) {
    assert.equal(run.discardedSpans, 14); assert.equal(run.spans.length, 6); assert.equal(run.spans[0]!.span, 15);
  }
});

test('the production awaits, bounded parser and independent V1 report fallback remain visibly wired', async () => {
  for (const [file, names] of [
    ['../../../src/state/recovery-closure.ts', ['publication_recovery']],
    ['../../../src/state/publication-invocation.ts', ['publication_completion_recovery']],
    ['../../../src/state/store.ts', ['terminal_retirement_recovery']],
    ['../../../src/state/run-result.ts', ['result_recovery']],
    ['../../../src/state/publication-finalization.ts', ['publication_received_prepare']],
    ['../../../src/state/publication-settlement.ts', ['publication_settlement_prepare', 'publication_settlement',
      'publication_received_settlement_prepare', 'publication_received_settlement']]
  ] as const) {
    const source = await readFile(new URL(file, import.meta.url), 'utf8');
    for (const name of names) assert(source.includes(`'${name}'`));
  }
  const journey = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  assert(journey.includes('terminalDeadlineRunId: publicationDeadlineRunId'));
  assert(journey.includes('run.runId === publicationDeadlineRunId'));
  assert(journey.includes('V2 absence/malformed data cannot discard V1 observations'));
  const workRead = journey.indexOf('const work = readInstalledPublicationWorkJournal(text,');
  assert(journey.indexOf("assert(Date.now() < logBy, 'actual publication work journal exceeded five seconds'); assertRetained();", workRead) > workRead);
  const settlement = await readFile(new URL('../../../src/state/publication-settlement.ts', import.meta.url), 'utf8');
  for (const name of ['preparePublicationSettlement', 'preparePublicationReceivedSettlement']) {
    const start = settlement.indexOf(`export async function ${name}(`), next = settlement.indexOf('\nexport ', start + 1);
    const body = settlement.slice(start, next < 0 ? undefined : next);
    assert(body.includes('})().finally(() => { binding.settling = undefined; }));'),
      'the end observation follows the original returned settlement promise, including its existing finally');
  }
  assert.deepEqual(INSTALLED_PUBLICATION_WORK_V2, ['publication_recovery', 'publication_completion_recovery',
    'publication_settlement_prepare', 'publication_settlement', 'publication_received_prepare',
    'publication_received_settlement_prepare', 'publication_received_settlement', 'terminal_retirement_recovery', 'result_recovery',
    'terminal_cancel_authority', 'terminal_cancel_material', 'terminal_cancel_control', 'terminal_cancel_stop',
    'run_cancel_channel', 'run_cancel_load', 'run_cancel_stop']);
});

test('malformed V2 cannot invoke a getter, leak private text or poison the original valid exit summary', () => {
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    const row={kind:'publication_work_v2',runId:${JSON.stringify(runId)},span:1,work:'publication_recovery',event:'begin',elapsedMs:0};
    Object.defineProperty(row,'origin',{enumerable:true,get(){throw Error('private-fixture-secret');}});d.publish(row);
    d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{}});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
  assert.equal(child.stderr.includes('private-fixture-secret'), false);
  const text = journal(child.stderr.trimEnd().split('\n'));
  assert.throws(() => readInstalledPublicationWorkJournal(text, sender));
  assert.equal(readInstalledStoreDiagnosticJournal(text, sender)!.schedulerFailures, 0);
});

test('the fixed 64-Run diagnostic tracker bound never refuses or delays the 65th original operation', () => {
  const moduleUrl = new URL('../../../src/state/installed-run-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', `
    import{channel}from'node:diagnostics_channel';const d=channel('cliq.installed.run.failures.v1');let rows=0,calls=0;
    const observe=()=>rows++;d.subscribe(observe);
    const {observeInstalledPublicationWork}=await import(${JSON.stringify(moduleUrl)});
    for(let i=0;i<65;i++){const result=await observeInstalledPublicationWork(i.toString(36).padStart(43,'a'),'publication_recovery',async()=>++calls);if(result!==calls)throw Error('original value changed');}
    d.unsubscribe(observe);process.stdout.write(calls+':'+rows);
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
  assert.equal(child.stdout, '65:128'); assert.equal(child.stderr, '');
});

test('terminal cancel consumers use the original bounded V2 sink and retain a pending original stop consumer', () => {
  // Ordinary promises and real child stdio only, never native/Run authority.
  const moduleUrl = new URL('../../../src/state/installed-run-diagnostics.ts', import.meta.url).href;
  const names = ['terminal_cancel_authority', 'terminal_cancel_material', 'terminal_cancel_control', 'terminal_cancel_stop'];
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval',
    `import {createRequire} from 'node:module';const require=createRequire(import.meta.url);` + INSTALLED_STORE_DIAGNOSTIC_BANNER + `
      const {observeInstalledPublicationWork}=await import(${JSON.stringify(moduleUrl)});
      const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
      for(let n=0;n<8;n++)await observeInstalledPublicationWork(${JSON.stringify(runId)},'result_recovery',async()=>n);
      for(const work of ${JSON.stringify(names.slice(0, 3))})await observeInstalledPublicationWork(${JSON.stringify(runId)},work,async()=>23);
      let release;const joined=new Promise(resolve=>release=resolve);
      const pending=observeInstalledPublicationWork(${JSON.stringify(runId)},'terminal_cancel_stop',async()=>{await joined;return 19;});
      d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:1,retainedFailures:0,globalFailure:false,phases:{}});
      release();if(await pending!==19)throw Error('original consumer result changed');
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null); assert.equal(child.stdout, '');
  const rows = child.stderr.trimEnd().split('\n'); assert(rows.length <= 80);
  const workRows = rows.filter(row => row.startsWith(prefix)); assert.equal(workRows.length, 2);
  assert(workRows.every(row => Buffer.byteLength(row) + 1 <= 4096));
  assert(Buffer.byteLength(workRows.join('\n')) <= 8192);
  const data = readInstalledPublicationWorkJournal(journal(rows), sender)!;
  assert.deepEqual(data.snapshots.map(snapshot => snapshot.boundary), ['stop', 'exit']);
  for (const snapshot of data.snapshots) {
    assert.equal(snapshot.runs.length, 1); const run = snapshot.runs[0]!;
    assert.equal(run.runId, runId); assert.equal(run.spans.length, 6); assert.equal(run.discardedSpans, 6);
    assert.deepEqual(run.spans.slice(-4).map(span => span.work), names);
  }
  assert.equal(data.snapshots[0]!.runs[0]!.spans.at(-1)!.outcome, 'pending');
  assert.equal(data.snapshots[0]!.runs[0]!.spans.at(-1)!.endedMs, null);
  assert.equal(data.snapshots[1]!.runs[0]!.spans.at(-1)!.outcome, 'fulfilled');
  assert.equal(readInstalledStoreDiagnosticJournal(journal(rows), sender)!.schedulerFailuresBeforeStop, 0);
  assert.throws(() => readInstalledPublicationWorkJournal(journal(rows).replace('terminal_cancel_stop', 'terminal_cancel_private'), sender));
});
