// Real child pipes carrying fixed data, not a Supervisor or native death proof.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { test } from 'node:test';

test('one accepted original Stop entry emits a fixed single-driver phase without changing its exit summary', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish({kind:'store_stop',
      driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{publication_prepare_physical:1}});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stderr, 'CLIQ_STORE_STOP_PHASE_V1:publication_prepare_physical\n' +
    'CLIQ_STORE_DIAG_V1:begin:0:0\nCLIQ_STORE_DIAG_V1:scheduler_window:0\nCLIQ_STORE_DIAG_V1:stop:1:0:0:0:0\n' +
    'CLIQ_STORE_DIAG_V1:phase:publication_prepare_physical:1\nCLIQ_STORE_DIAG_V1:end\n',
    'only the accepted original Stop entry can add its independent fixed phase marker');
});

test('a live single-driver Stop snapshot exposes each preparation label before exit but never a joined result', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const { readInstalledStoreStopPhaseJournal, readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const phases = ['publication_prepare_read', 'publication_prepare_grant', 'publication_prepare_cut',
    'publication_prepare_physical', 'publication_prepare_admit'];
  const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
  const journal = (rows: string[]) => rows.map(MESSAGE => JSON.stringify({ _UID: '1000', _PID: '2000',
    _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n');
  for (const phase of phases) {
    const child = spawn(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
      require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish({kind:'store_stop',
        driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{[${JSON.stringify(phase)}]:1}});
      process.stdin.resume(); require('node:fs').writeSync(1,'ready\\n');
    `], { stdio: ['pipe', 'pipe', 'pipe'] });
    const marker = `CLIQ_STORE_STOP_PHASE_V1:${phase}\n`;
    let stdout = '', stderr = '', readyResolve!: () => void;
    const ready = new Promise<void>(resolve => { readyResolve = resolve; });
    const observe = () => { if (stdout === 'ready\n' && stderr === marker) readyResolve(); };
    child.stdout.on('data', bytes => { stdout += bytes.toString(); observe(); });
    child.stderr.on('data', bytes => { stderr += bytes.toString(); observe(); });
    const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
    });
    const timeout = AbortSignal.timeout(5000);
    const expired = new Promise<never>((_, reject) => timeout.addEventListener('abort',
      () => reject(new Error('owned Stop-phase child did not join')), { once: true }));
    try {
      await Promise.race([ready, joined.then(() => { throw new Error('owned child exited before original Stop-phase observation'); }), expired]);
      assert.equal(child.exitCode, null); assert.equal(child.signalCode, null); assert.equal(stderr, marker);
      const rows = [marker.trimEnd()];
      assert.deepEqual(readInstalledStoreStopPhaseJournal(journal(rows), sender), { phase });
      assert.equal(readInstalledStoreDiagnosticJournal(journal(rows), sender), undefined, 'a live Stop entry cannot manufacture an exit summary');
      child.stdin.end();
      assert.deepEqual(await Promise.race([joined, expired]), { code: 0, signal: null });
      const finalRows = stderr.trimEnd().split('\n');
      assert.equal(finalRows.filter(row => row.startsWith('CLIQ_STORE_STOP_PHASE')).length, 1);
      assert.deepEqual(readInstalledStoreDiagnosticJournal(journal(finalRows), sender)!.stop.phases, { [phase]: 1 });
      assert.deepEqual(readInstalledStoreStopPhaseJournal(journal(finalRows), sender), { phase });
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await joined;
    }
  }
});

test('the original six live arrivals and one maximal Stop label remain below their existing combined byte budget', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const { INSTALLED_PUBLICATION_DIAGNOSTIC_PHASES, INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES } = await import('../../../src/state/installed-run-diagnostics.js');
  const longest = [...INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES].sort((left, right) => right.length - left.length)[0]!;
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    for(const phase of ${JSON.stringify(INSTALLED_PUBLICATION_DIAGNOSTIC_PHASES)})d.publish({kind:'publication_phase',phase});
    d.publish({kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{[${JSON.stringify(longest)}]:1}});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  const rows = child.stderr.trimEnd().split('\n');
  const arrival = rows.filter(row => row.startsWith('CLIQ_PUBLICATION_STAGE_V1:'));
  const stop = rows.filter(row => row.startsWith('CLIQ_STORE_STOP_PHASE_V1:'));
  assert.equal(arrival.length, 6); assert.deepEqual(stop, [`CLIQ_STORE_STOP_PHASE_V1:${longest}`]);
  assert(Buffer.byteLength(stop[0]! + '\n') <= 96, 'the independent fixed Stop label retains its original per-marker bound');
  assert(Buffer.byteLength([...arrival, ...stop].join('\n') + '\n') < 512, 'all seven possible live records fit the unchanged combined 512-byte budget');
  const summary = rows.filter(row => row.startsWith('CLIQ_STORE_DIAG_V1:'));
  assert(summary.length <= 16 && Buffer.byteLength(summary.join('\n') + '\n') <= 4096 && summary.every(row => row.length <= 255));
});

test('ambiguous or invalid Stop data cannot invent a single-driver label or invoke hostile fields', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const values = [
    `{...row,driverTasks:0,phases:{}}`, `{...row,driverTasks:1,phases:{}}`, `{...row,driverTasks:2}`,
    `{...row,driverTasks:2,phases:{publication_prepare_read:1,publication_prepare_cut:1}}`,
    `{...row,phases:{publication_prepare_read:2}}`, `{...row,driverTasks:'1'}`, `{...row,phases:{unknown:1}}`,
    ...['submit_request', 'submit_preflight_authority', 'submit_source_capture', 'submit_assembly', 'submit_final_admission',
      'submit_postcommit_load'].map(phase => `{...row,phases:{${phase}:1}}`),
    `Object.defineProperty({...row},'driverTasks',{get:bad})`,
    `{...row,phases:Object.defineProperty({},'publication_prepare_read',{enumerable:true,get:bad})}`,
    `{...row,phases:new Proxy(row.phases,{get:bad,ownKeys:bad,getPrototypeOf:bad,getOwnPropertyDescriptor:bad})}`,
    `new Proxy(row,{get:bad,ownKeys:bad,getPrototypeOf:bad,getOwnPropertyDescriptor:bad})`, `{...row,path:'inert forbidden field'}`
  ];
  for (const value of values) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
      let accesses=0; const bad=()=>{accesses++;throw Error('inert private input')};
      const row={kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,
        phases:{publication_prepare_read:1}};
      require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish(${value});
      require('node:fs').writeSync(1,'accesses:'+accesses);
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
    assert.equal(child.stdout, 'accesses:0');
    assert.equal(child.stderr.includes('CLIQ_STORE_STOP_PHASE'), false, 'only one unambiguous accepted original Stop may emit the phase');
  }
});

test('a failed Stop sink is not retried, repeated Stop cannot add a second label, and original error and live progress survive', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `
    const fs=require('node:fs'), write=fs.writeSync;let attempts=0;
    fs.writeSync=(fd,text,...args)=>{if(fd===2&&String(text).startsWith('CLIQ_STORE_STOP_PHASE_V1:')){
      attempts++;throw Error('inert unavailable Stop sink');}return write(fd,text,...args)};
  ` + INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    const original=Error('inert original operation failure');let same=false;
    const stop={kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{publication_prepare_read:1}};
    try{try{throw original}catch(error){d.publish(stop);throw error}}catch(error){same=error===original}
    d.publish(stop);d.publish({kind:'publication_phase',phase:'publication_prepare'});
    fs.writeSync(1,'original:'+same+';attempts:'+attempts);
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'original:true;attempts:1');
  assert.equal(child.stderr, 'CLIQ_PUBLICATION_STAGE_V1:1:publication_prepare\nCLIQ_STORE_DIAG_V1:truncated\n');
  const repeated = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    for(let index=0;index<2;index++)d.publish({kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,
      globalFailure:false,phases:{publication_prepare_read:1}});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(repeated.error, undefined); assert.equal(repeated.signal, null); assert.equal(repeated.status, 0);
  assert.equal(repeated.stderr, 'CLIQ_STORE_STOP_PHASE_V1:publication_prepare_read\nCLIQ_STORE_DIAG_V1:truncated\n',
    'the first real accepted Stop observation remains, but duplicate input can never emit a second snapshot or valid summary');
});

test('every submit await stage round-trips through the unchanged admission envelope but never publication markers', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const { readInstalledStoreDiagnosticJournal, readInstalledPublicationStageJournal } = await import('./installed-store-diagnostic-journal.js');
  const stages = ['submit_request', 'submit_preflight_authority', 'submit_source_capture', 'submit_assembly',
    'submit_final_admission', 'submit_postcommit_load'];
  const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
  const journal = (messages: string[]) => messages.map(MESSAGE => JSON.stringify({ _UID: '1000', _PID: '2000',
    _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n');
  for (const stage of stages) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
      const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
      d.publish({kind:'publication_phase',phase:${JSON.stringify(stage)}});
      d.publish({kind:'apply_failure',stage:${JSON.stringify(stage)},closing:true,errorClass:'kernel',code:'LEASE_FENCED',sqliteCode:null});
      d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:1,retainedFailures:0,globalFailure:false,phases:{}});
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
    assert.equal(child.stderr, 'CLIQ_STORE_DIAG_V1:begin:1:0\n' +
      `CLIQ_STORE_DIAG_V1:apply:${stage}:1:kernel:LEASE_FENCED:-\n` +
      'CLIQ_STORE_DIAG_V1:scheduler_window:0\nCLIQ_STORE_DIAG_V1:stop:0:0:1:0:0\nCLIQ_STORE_DIAG_V1:end\n');
    const rows = child.stderr.trimEnd().split('\n');
    assert(rows.length <= 16 && Buffer.byteLength(child.stderr) <= 4096 && rows.every(row => row.length <= 255));
    const summary = readInstalledStoreDiagnosticJournal(journal(rows), sender)!;
    assert.equal(summary.applyFailures, 1);
    assert.deepEqual(summary.firstApplyFailure, { stage, closing: true, errorClass: 'kernel', code: 'LEASE_FENCED', sqliteCode: null });
    assert.equal(readInstalledPublicationStageJournal(journal(rows), sender), undefined);
    assert.throws(() => readInstalledPublicationStageJournal(journal([`CLIQ_PUBLICATION_STAGE_V1:1:${stage}`]), sender));
    assert.throws(() => readInstalledStoreDiagnosticJournal(journal(rows.map(row => row.replace(stage, stage + '_unknown'))), sender));
  }
});

test('publication progress writes each first-seen phase immediately in actual arrival order without changing the exit summary', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const phases = ['publication_prepare', 'publication_select', 'publication_worker_activate',
    'publication_roots_open', 'publication_dispatch', 'publication_settlement'];
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    for (const phase of ${JSON.stringify(phases)}) {
      d.publish({kind:'publication_phase',phase}); d.publish({kind:'publication_phase',phase});
    }
    d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{}});
    require('node:fs').writeSync(1,'operation unchanged\\n');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'operation unchanged\n');
  const progress = phases.map((phase, index) => `CLIQ_PUBLICATION_STAGE_V1:${index + 1}:${phase}\n`).join('');
  assert(progress.length < 512);
  assert.equal(child.stderr, progress + 'CLIQ_STORE_DIAG_V1:begin:0:0\nCLIQ_STORE_DIAG_V1:scheduler_window:0\n' +
    'CLIQ_STORE_DIAG_V1:stop:0:0:0:0:0\nCLIQ_STORE_DIAG_V1:end\n');
});

test('preparation details round-trip only through the original bounded exit summary, not live arrival markers', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const { readInstalledStoreDiagnosticJournal } = await import('./installed-store-diagnostic-journal.js');
  const phases = ['publication_prepare_read', 'publication_prepare_grant', 'publication_prepare_cut',
    'publication_prepare_physical', 'publication_prepare_admit'];
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    d.publish({kind:'publication_phase',phase:'publication_prepare'});
    for(const phase of ${JSON.stringify(phases)}) {
      d.publish({kind:'publication_phase',phase});
      d.publish({kind:'scheduler_failure',origin:'drive',phase,closing:false,errorClass:'other',code:'none',sqliteCode:null});
    }
    d.publish({kind:'store_stop',driverTasks:5,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,
      phases:Object.fromEntries(${JSON.stringify(phases)}.map(phase=>[phase,1]))});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  const rows = child.stderr.trimEnd().split('\n');
  assert.deepEqual(rows.filter(row => row.startsWith('CLIQ_PUBLICATION_STAGE_V1:')),
    ['CLIQ_PUBLICATION_STAGE_V1:1:publication_prepare']);
  const summaryRows = rows.filter(row => row.startsWith('CLIQ_STORE_DIAG_V1:'));
  assert(summaryRows.length <= 16); assert(Buffer.byteLength(summaryRows.join('\n')) <= 4096);
  assert(summaryRows.every(row => Buffer.byteLength(row) <= 255));
  const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
  const journal = summaryRows.map(MESSAGE => JSON.stringify({ _UID: '1000', _PID: '2000', _TRANSPORT: 'stdout',
    _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n');
  const summary = readInstalledStoreDiagnosticJournal(journal, sender)!;
  assert.equal(summary.schedulerFailures, 5); assert.equal(summary.schedulerFailuresBeforeStop, 5);
  assert.equal(summary.firstSchedulerFailure!.phase, phases[0]);
  assert.equal(summary.lastSchedulerFailure!.phase, phases.at(-1));
  assert.deepEqual(summary.stop.phases, Object.fromEntries(phases.map(phase => [phase, 1])));
  assert.equal(Object.hasOwn(summary, 'qualified'), false);
});

test('malformed identifiable progress data cannot invoke getters or poison an original valid summary', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    let reads=0; const bad=()=>{reads++;throw Error('private')};
    const row={kind:'publication_phase',phase:'publication_select'};
    for(const value of [Object.defineProperty({...row},'phase',{get:bad}), {...row,phase:new Proxy({},{get:bad})},
      {...row,phase:'publication_unknown'}, {...row,phase:['publication_select']}, {...row,path:'private'},
      {...row,[Symbol('private')]:1}, Object.defineProperty({...row},'phase',{value:'publication_select',enumerable:false})]) d.publish(value);
    d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{}});
    require('node:fs').writeSync(1,'accesses:'+reads);
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'accesses:0');
  assert.equal(child.stderr, 'CLIQ_STORE_DIAG_V1:begin:0:0\nCLIQ_STORE_DIAG_V1:scheduler_window:0\n' +
    'CLIQ_STORE_DIAG_V1:stop:0:0:0:0:0\nCLIQ_STORE_DIAG_V1:end\n');
});

test('failed progress sinks are contained and never retry an already observed phase', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `
    const fs=require('node:fs'), originalWrite=fs.writeSync; let attempts=0;
    fs.writeSync=(fd,...args)=>{if(fd===2){attempts++;throw Error('private sink failure')};return originalWrite(fd,...args)};
  ` + INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    for(let index=0;index<100;index++)d.publish({kind:'publication_phase',phase:'publication_select'});
    fs.writeSync(1,'operation unchanged:'+attempts);
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'operation unchanged:1'); assert.equal(child.stderr, '');
});

test('a real live child writes progress before exit without claiming a joined result', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawn(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d=require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    d.publish({kind:'publication_phase',phase:'publication_prepare'});
    process.stdin.resume(); require('node:fs').writeSync(1,'ready\\n');
  `], { stdio: ['pipe', 'pipe', 'pipe'] });
  const marker = 'CLIQ_PUBLICATION_STAGE_V1:1:publication_prepare\n';
  let stdout = '', stderr = '', readyResolve!: () => void;
  const ready = new Promise<void>(resolve => { readyResolve = resolve; });
  const observe = () => { if (stdout === 'ready\n' && stderr === marker) readyResolve(); };
  child.stdout.on('data', bytes => { stdout += bytes.toString(); observe(); });
  child.stderr.on('data', bytes => { stderr += bytes.toString(); observe(); });
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const timeout = AbortSignal.timeout(5000);
  const expired = new Promise<never>((_, reject) => timeout.addEventListener('abort', () => reject(new Error('owned progress child did not join')), { once: true }));
  try {
    await Promise.race([ready, joined.then(() => { throw new Error('owned child exited before live progress observation'); }), expired]);
    assert.equal(child.exitCode, null); assert.equal(child.signalCode, null); assert.equal(stderr, marker);
    child.stdin.end();
    assert.deepEqual(await Promise.race([joined, expired]), { code: 0, signal: null });
    assert.equal(stderr, marker, 'progress has no fabricated exit summary, completion or join marker');
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await joined;
  }
});

test('the trusted exit banner retains the last original scheduler failure and the actual pre-stop count', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    d.publish({kind:'scheduler_failure',origin:'drive',phase:'drive_verify',closing:false,errorClass:'other',code:'none',sqliteCode:null});
    d.publish({kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:1,globalFailure:false,phases:{publication_prepare:1}});
    d.publish({kind:'scheduler_failure',origin:'drive',phase:'publication_prepare',closing:true,errorClass:'other',code:'none',sqliteCode:null});
    require('node:fs').writeSync(1, 'operation unchanged\\n');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'operation unchanged\n');
  assert.equal(child.stderr, 'CLIQ_STORE_STOP_PHASE_V1:publication_prepare\nCLIQ_STORE_DIAG_V1:begin:0:2\n' +
    'CLIQ_STORE_DIAG_V1:scheduler:drive:drive_verify:0:other:none:-\n' +
    'CLIQ_STORE_DIAG_V1:scheduler_window:1\n' +
    'CLIQ_STORE_DIAG_V1:scheduler_last:drive:publication_prepare:1:other:none:-\n' +
    'CLIQ_STORE_DIAG_V1:stop:1:0:0:1:0\n' +
    'CLIQ_STORE_DIAG_V1:phase:publication_prepare:1\nCLIQ_STORE_DIAG_V1:end\n');
});

test('a real failure after the stop snapshot does not disappear when its pre-stop count was zero', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    d.publish({kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{publication_select:1}});
    const failure = {kind:'scheduler_failure',origin:'drive',phase:'publication_select',closing:true,errorClass:'other',code:'none',sqliteCode:null};
    d.publish(failure); failure.phase='private'; failure.closing=false;
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stderr, 'CLIQ_STORE_STOP_PHASE_V1:publication_select\nCLIQ_STORE_DIAG_V1:begin:0:1\n' +
    'CLIQ_STORE_DIAG_V1:scheduler:drive:publication_select:1:other:none:-\n' +
    'CLIQ_STORE_DIAG_V1:scheduler_window:0\n' +
    'CLIQ_STORE_DIAG_V1:scheduler_last:drive:publication_select:1:other:none:-\n' +
    'CLIQ_STORE_DIAG_V1:stop:1:0:0:0:0\n' +
    'CLIQ_STORE_DIAG_V1:phase:publication_select:1\nCLIQ_STORE_DIAG_V1:end\n');
});

test('a failed diagnostic exit write does not replace the real child operation or keep it alive', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `
    const fs = require('node:fs'), originalWrite = fs.writeSync;
    fs.writeSync = (fd, ...args) => { if (fd === 2) throw Error('diagnostic output unavailable'); return originalWrite(fd, ...args); };
  ` + INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{}});
    fs.writeSync(1,'operation unchanged\\n');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'operation unchanged\n'); assert.equal(child.stderr, '');
});

test('the exit banner appends only the first actual authorization failure and count without changing old frames', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    d.publish({kind:'authorization_failure',stage:'transaction',errorClass:'kernel',code:'REVISION_CONFLICT',sqliteCode:null});
    d.publish({kind:'authorization_failure',stage:'publish_response',errorClass:'sqlite',code:'ERR_SQLITE_ERROR',sqliteCode:1});
    d.publish({kind:'store_stop',driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{}});
    require('node:fs').writeSync(1, 'operation unchanged\\n');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'operation unchanged\n');
  assert.equal(child.stderr, 'CLIQ_STORE_DIAG_V1:begin:0:0\n' +
    'CLIQ_STORE_DIAG_V1:scheduler_window:0\n' +
    'CLIQ_STORE_DIAG_V1:authorization:2:transaction:kernel:REVISION_CONFLICT:-\n' +
    'CLIQ_STORE_DIAG_V1:stop:0:0:0:0:0\nCLIQ_STORE_DIAG_V1:end\n');
});

test('the trusted banner emits its bounded fixed summary only as the real child exits', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const d = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    d.publish({kind:'apply_failure',stage:'postcommit_load',closing:false,errorClass:'sqlite',code:'ERR_SQLITE_ERROR',sqliteCode:1});
    d.publish({kind:'scheduler_failure',origin:'drive',phase:'drive_agent',closing:false,errorClass:'kernel',code:'RECOVERY_REQUIRED',sqliteCode:null});
    d.publish({kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:1,globalFailure:false,phases:{drive_agent:1}});
    require('node:fs').writeSync(1, 'operation unchanged\\n');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, 'operation unchanged\n');
  assert.equal(child.stderr, 'CLIQ_STORE_STOP_PHASE_V1:drive_agent\nCLIQ_STORE_DIAG_V1:begin:1:1\n' +
    'CLIQ_STORE_DIAG_V1:apply:postcommit_load:0:sqlite:ERR_SQLITE_ERROR:1\n' +
    'CLIQ_STORE_DIAG_V1:scheduler:drive:drive_agent:0:kernel:RECOVERY_REQUIRED:-\n' +
    'CLIQ_STORE_DIAG_V1:scheduler_window:1\n' +
    'CLIQ_STORE_DIAG_V1:scheduler_last:drive:drive_agent:0:kernel:RECOVERY_REQUIRED:-\n' +
    'CLIQ_STORE_DIAG_V1:stop:1:0:0:1:0\n' +
    'CLIQ_STORE_DIAG_V1:phase:drive_agent:1\nCLIQ_STORE_DIAG_V1:end\n');
});

test('a real live child emits no summary before its stdin ends and every owned pipe joins', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawn(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish({kind:'store_stop',
      driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{}});
    process.stdin.resume(); require('node:fs').writeSync(1,'ready\\n');
  `], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const ready = new Promise<void>(resolve => child.stdout.on('data', data => { stdout += data.toString(); if (stdout === 'ready\n') resolve(); }));
  child.stderr.on('data', data => { stderr += data.toString(); });
  const timeout = AbortSignal.timeout(5000);
  try {
    await Promise.race([ready, new Promise<never>((_, reject) => timeout.addEventListener('abort', () => reject(new Error('owned child did not become ready')), { once: true }))]);
    assert.equal(stderr, ''); assert.equal(child.exitCode, null);
    child.stdin.end();
    const actual = await Promise.race([joined, new Promise<never>((_, reject) => timeout.addEventListener('abort', () => reject(new Error('owned child pipes did not join')), { once: true }))]);
    assert.deepEqual(actual, { code: 0, signal: null });
    assert.equal(stderr, 'CLIQ_STORE_DIAG_V1:begin:0:0\nCLIQ_STORE_DIAG_V1:scheduler_window:0\nCLIQ_STORE_DIAG_V1:stop:0:0:0:0:0\nCLIQ_STORE_DIAG_V1:end\n');
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await joined;
  }
});

test('invalid diagnostic tuples yield only the fixed unavailable marker without accessing hostile data', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const snippets = [
    `Object.defineProperty({},'kind',{get(){throw new Error('private')}})`,
    `new Proxy({},{ownKeys(){throw new Error('private')},getPrototypeOf(){throw new Error('private')}})`,
    `{kind:'apply_failure',stage:['prepare'],closing:false,errorClass:'kernel',code:'RECOVERY_REQUIRED',sqliteCode:null}`,
    `{kind:'apply_failure',stage:'prepare',closing:false,errorClass:'kernel',code:'ERR_SQLITE_ERROR',sqliteCode:1}`,
    `{kind:'apply_failure',stage:'prepare',closing:false,errorClass:'other',code:'private',sqliteCode:null}`,
    `{kind:'authorization_failure',stage:'transaction',errorClass:'kernel',code:'REVISION_CONFLICT'}`,
    `{kind:'authorization_failure',stage:'unknown',errorClass:'kernel',code:'REVISION_CONFLICT',sqliteCode:null}`,
    `{kind:'authorization_failure',stage:['transaction'],errorClass:'kernel',code:'REVISION_CONFLICT',sqliteCode:null}`,
    `{kind:'authorization_failure',stage:'transaction',errorClass:'kernel',code:'REVISION_CONFLICT',sqliteCode:null,closing:false}`,
    `{kind:'authorization_failure',stage:'transaction',errorClass:'kernel',code:'REVISION_CONFLICT',sqliteCode:null,path:'private'}`,
    `{kind:'authorization_failure',stage:'transaction',errorClass:'kernel',code:'ERR_SQLITE_ERROR',sqliteCode:1}`,
    `{kind:'authorization_failure',stage:'transaction',errorClass:'other',code:'private',sqliteCode:null}`,
    `{kind:'store_stop',driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{scheduled:1}}`,
    `{kind:'store_stop',driverTasks:1,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:Object.defineProperty({},'scheduled',{enumerable:true,get(){throw new Error('private')}})}`,
    `{kind:'store_stop',driverTasks:9,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:{scheduled:1,drive_material:1,drive_agent:1,drive_retirement:1,drive_verify:1,drive_finalize:1,terminal_retirement:1,result_recovery:1,result_basis:1}}`
  ];
  for (const snippet of snippets) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
      require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish(${snippet});
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
    assert.equal(child.stdout, ''); assert.equal(child.stderr, 'CLIQ_STORE_DIAG_V1:truncated\n');
  }
});

test('authorization tuple accessors and Proxy traps never run and cannot reveal private fields', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const variants = [
    `Object.defineProperty({...row},'stage',{get:bad})`, `Object.defineProperty({...row},'code',{get:bad})`,
    `Object.defineProperty({...row},'sqliteCode',{get:bad})`, `{...row,[Symbol('private')]:1}`,
    `new Proxy(row,{get:bad,ownKeys:bad,getPrototypeOf:bad,getOwnPropertyDescriptor:bad})`,
  ];
  for (const value of variants) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
      let reads=0; const bad=()=>{reads++;throw Error('private')};
      const row={kind:'authorization_failure',stage:'transaction',errorClass:'kernel',code:'REVISION_CONFLICT',sqliteCode:null};
      require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish(${value});
      require('node:fs').writeSync(1,'accesses:'+reads);
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
    assert.equal(child.stdout, 'accesses:0'); assert.equal(child.stderr, 'CLIQ_STORE_DIAG_V1:truncated\n');
  }
});

test('scheduler tuple accessors, proxies and unknown publication phases remain unavailable without inspecting them', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const variants = [`Object.defineProperty({...row},'phase',{get:bad})`, `Object.defineProperty({...row},'closing',{get:bad})`,
    `new Proxy(row,{get:bad,ownKeys:bad,getPrototypeOf:bad,getOwnPropertyDescriptor:bad})`,
    `{...row,phase:'publication_unknown'}`, `{...row,path:'private'}`, `{...row,[Symbol('private')]:1}`];
  for (const value of variants) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
      let reads=0; const bad=()=>{reads++;throw Error('private')};
      const row={kind:'scheduler_failure',origin:'drive',phase:'publication_prepare',closing:true,errorClass:'other',code:'none',sqliteCode:null};
      require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1').publish(${value});
      require('node:fs').writeSync(1,'accesses:'+reads);
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
    assert.equal(child.stdout, 'accesses:0'); assert.equal(child.stderr, 'CLIQ_STORE_DIAG_V1:truncated\n');
  }
});

test('an unused qualification subscriber emits no exit output or keepalive', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
