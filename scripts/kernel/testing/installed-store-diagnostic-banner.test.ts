// Real child pipes carrying fixed data, not a Supervisor or native death proof.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { test } from 'node:test';

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
  assert.equal(child.stderr, 'CLIQ_STORE_DIAG_V1:begin:1:1\n' +
    'CLIQ_STORE_DIAG_V1:apply:postcommit_load:0:sqlite:ERR_SQLITE_ERROR:1\n' +
    'CLIQ_STORE_DIAG_V1:scheduler:drive:drive_agent:0:kernel:RECOVERY_REQUIRED:-\n' +
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
    assert.equal(stderr, 'CLIQ_STORE_DIAG_V1:begin:0:0\nCLIQ_STORE_DIAG_V1:stop:0:0:0:0:0\nCLIQ_STORE_DIAG_V1:end\n');
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

test('an unused qualification subscriber emits no exit output or keepalive', async () => {
  const { INSTALLED_STORE_DIAGNOSTIC_BANNER } = await import('./installed-store-diagnostic-banner.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
