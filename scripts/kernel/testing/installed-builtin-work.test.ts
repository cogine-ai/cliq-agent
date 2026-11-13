// Real self-owned CAS and child pipes; serialized diagnostics confer no authority.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { channel } from 'node:diagnostics_channel';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { ContentAddressedStore } from '../../../src/state/cas.js';
import { INSTALLED_BUILTIN_WORK_CHANNEL, noteInstalledBuiltinWorkPhase } from '../../../src/state/installed-work-diagnostics.js';
import { INSTALLED_RUN_FAILURE_CHANNEL, noteInstalledStoreStop } from '../../../src/state/installed-run-diagnostics.js';
import { INSTALLED_BUILTIN_WORK_DIAGNOSTIC_BANNER as banner } from './installed-builtin-work-banner.js';
import { readInstalledBuiltinWorkJournal } from './installed-store-diagnostic-journal.js';

test('fixed phase observations count actual small and threaded CAS reads and ignore invalid Stop input', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-builtin-work-')), cas = new ContentAddressedStore(root);
  const packets: any[] = [], subscriber = (value: unknown) => packets.push(value), ignore = () => {};
  const diagnostic = channel(INSTALLED_BUILTIN_WORK_CHANNEL), stop = channel(INSTALLED_RUN_FAILURE_CHANNEL);
  diagnostic.subscribe(subscriber); stop.subscribe(ignore);
  try {
    const small = Buffer.alloc(4096, 1), large = Buffer.alloc(8 * 1024 * 1024, 2);
    const a = await cas.publish(small), b = await cas.publish(large);
    noteInstalledBuiltinWorkPhase('tool_select'); const first = packets.at(-1);
    assert.deepEqual(await cas.read(a), small); await cas.verifyChunks(b, large.length);
    noteInstalledBuiltinWorkPhase('tool_prepare'); const last = packets.at(-1);
    assert.equal(last.readsStarted - first.readsStarted, 2); assert.equal(last.readsSettled - first.readsSettled, 2);
    assert.equal(last.returnedBytes - first.returnedBytes, small.length + large.length);
    assert(Object.isFrozen(last)); assert(!JSON.stringify(packets).includes(root));
    noteInstalledBuiltinWorkPhase('private input'); noteInstalledStoreStop({ unexpected: true });
    assert.equal(packets.length, 2);
    noteInstalledStoreStop({ driverTasks: 0, agentLoads: 0, admissions: 0, retainedFailures: 0, globalFailure: false, phases: [] });
    assert.equal(packets.at(-1).phase, 'stop_entry');
  } finally { diagnostic.unsubscribe(subscriber); stop.unsubscribe(ignore); await rm(root, { recursive: true, force: true }); }
});

const expected = { uid: 123, pid: 456, invocationId: 'a'.repeat(32) };
const journal = (message: string) => JSON.stringify({ _UID: '123', _PID: '456', _TRANSPORT: 'stdout',
  _SYSTEMD_INVOCATION_ID: expected.invocationId, MESSAGE: message });
function child(code: string, supervisor = true) {
  const result = spawnSync(process.execPath, ['--input-type=commonjs', '--eval',
    `process.argv[2]=${JSON.stringify(supervisor ? '--installed-supervisor' : '--other')};` + banner + `
    const d=require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_BUILTIN_WORK_CHANNEL)});
    const row={phase:'tool_select',readsStarted:0,readsSettled:0,returnedBytes:0,revalidatedBytes:0};
    ${code}`], { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  assert.equal(result.error, undefined); assert.equal(result.status, 0); assert.equal(result.signal, null); return result;
}

test('one bounded Stop-entry frame retains complete process windows without claiming exclusive costs or join', () => {
  const result = child(`d.publish(row);d.publish({...row,phase:'tool_release',readsStarted:3,readsSettled:2,returnedBytes:17,revalidatedBytes:23});
    d.publish({...row,phase:'stop_entry',readsStarted:7,readsSettled:5,returnedBytes:31,revalidatedBytes:41});
    d.publish({...row,private:'must not escape'});`);
  const lines = result.stderr.trim().split('\n'); assert.equal(lines.length, 1); assert(result.stderr.length <= 8192);
  const read = readInstalledBuiltinWorkJournal(journal(lines[0]!), expected)!;
  assert.equal(read.exclusiveStageCosts, false); assert.equal(read.runAttribution, false); assert.equal(read.boundary, 'stop_entry');
  assert.equal(read.byteAccounting, 'reported_at_read_callback_or_discard_worker_exit');
  assert.equal(read.inFlightDiscardBytesMayBeUnreported, true);
  assert.equal(read.pendingCasReadsAtStop, 2);
  assert.deepEqual(read.windows.map(row => [row.phase, row.entries, row.readsStarted, row.readsSettled, row.returnedBytes, row.revalidatedBytes]),
    [['tool_select', 1, 3, 2, 17, 23], ['tool_release', 1, 4, 3, 14, 18]]);
  assert.equal(read.windows.reduce((sum, row) => sum + row.elapsedMicros, 0), read.windowMicros);
  assert(!JSON.stringify(read).includes('qualified')); assert(Object.isFrozen(read.windows));
  for (const identity of [{ ...expected, pid: 457 }, { ...expected, uid: 124 }, { ...expected, invocationId: 'b'.repeat(32) }])
    assert.throws(() => readInstalledBuiltinWorkJournal(journal(lines[0]!), identity));
  const badSize = lines[0]!.split(':'); badSize[3] = '99';
  for (const bad of [badSize.join(':'), lines[0]!.replace('tool_select', 'private'),
    lines[0]! + ';tool_select,1,0,0,0,0,0,0,0', 'CLIQ_BUILTIN_WORK_V1:truncated'])
    assert.throws(() => readInstalledBuiltinWorkJournal(journal(bad), expected));
  assert.throws(() => readInstalledBuiltinWorkJournal(journal(lines[0]!) + '\n' + journal(lines[0]!), expected));
});

test('missing Stop and non-Supervisor composition emit no result and retain no timer', () => {
  assert.equal(child('d.publish(row);').stderr, '');
  assert.equal(child("d.publish(row);d.publish({...row,phase:'stop_entry'});", false).stderr, '');
});

test('malformed diagnostic data closes the numeric frame without getters, private strings or retries', () => {
  for (const mutation of ["{...row,private:'must-not-escape'}", "{...row,phase:'must-not-escape'}",
    "{...row,readsSettled:1}", "{...row,returnedBytes:-1}", "{...row,revalidatedBytes:Number.MAX_SAFE_INTEGER+1}",
    "Object.defineProperty({...row},'phase',{get:bad})", "new Proxy(row,{get:bad,ownKeys:bad,getPrototypeOf:bad})",
    "{...row,[Symbol('must-not-escape')]:1}"] ) {
    const result = child(`let accessed=0;const bad=()=>{accessed++;throw Error('must-not-escape')};d.publish(${mutation});
      d.publish({...row,phase:'stop_entry'});process.stdout.write(String(accessed));`);
    assert.equal(result.stdout, '0'); assert.equal(result.stderr, 'CLIQ_BUILTIN_WORK_V1:truncated\n');
  }
  const regression = child("d.publish({...row,returnedBytes:1});d.publish({...row,phase:'tool_release'});");
  assert.equal(regression.stderr, 'CLIQ_BUILTIN_WORK_V1:truncated\n');
});
