// Real V8 sampling in an inert child; no installed identity or authority.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { INSTALLED_CPU_DIAGNOSTIC_BANNER, readInstalledCpuJournal } from './installed-cpu-diagnostic.js';
import { INSTALLED_BUILTIN_WORK_CHANNEL } from '../../../src/state/installed-work-diagnostics.js';

const expected = { uid: 1001, pid: 1234, invocationId: 'a'.repeat(32) };
const journal = (message: string) => JSON.stringify({ _UID: '1001', _PID: '1234', _TRANSPORT: 'stdout',
  _SYSTEMD_INVOCATION_ID: expected.invocationId, MESSAGE: message });

test('the controlled sampler emits only fixed numeric buckets after actual V8 stop and disconnect', () => {
  const source = `process.argv[2]='--installed-supervisor';${INSTALLED_CPU_DIAGNOSTIC_BANNER}
    const d=require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_BUILTIN_WORK_CHANNEL)});
    let accesses=0;d.publish(Object.defineProperty({},'phase',{get(){accesses++;throw Error('private getter')}}));
    const prepare=()=>d.publish({phase:'tool_prepare'});
    for(let n=0;n<4;n++)prepare();
    function serializeCanonical(){const until=Date.now()+150;while(Date.now()<until)JSON.stringify({value:Math.random()});}
    setTimeout(()=>{serializeCanonical();prepare();serializeCanonical();prepare();
      setTimeout(()=>{d.publish({phase:'stop_entry'});console.log(accesses);},20);},20);`;
  const result = spawnSync(process.execPath, ['-e', source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout.trim(), '0');
  const sample = readInstalledCpuJournal(result.stderr.trim().split('\n').map(journal).join('\n'), expected);
  assert(sample.samples! > 0); assert(sample.buckets.canonical! > 0);
  assert.equal(Object.values(sample.buckets).reduce((a,b) => a!+b!,0), sample.samples);
  assert(sample.otherFunctionHashes.length <= 16);
  for (const row of sample.otherFunctionHashes) assert.match(row.sha256!, /^[0-9a-f]{64}$/u);
});

test('an early close refuses the incomplete sample and never keeps an inspector session alive', () => {
  const source = `process.argv[2]='--installed-supervisor';${INSTALLED_CPU_DIAGNOSTIC_BANNER}
    const d=require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_BUILTIN_WORK_CHANNEL)});
    for(let n=0;n<4;n++)d.publish({phase:'tool_prepare'});
    setTimeout(()=>d.publish({phase:'stop_entry'}),20);`;
  const result = spawnSync(process.execPath, ['-e', source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0); assert.equal(result.stderr.trim(), 'CLIQ_CPU_SAMPLE_V1:refused');
  assert.throws(() => readInstalledCpuJournal(journal(result.stderr.trim()), expected));
});

test('CPU observations retain original journal binding and closed cumulative counts', () => {
  const valid = 'CLIQ_CPU_SAMPLE_V1:2:5000:1:0:0:0:0:0:0:0:1';
  const rows = (value: string, other = 'CLIQ_CPU_OTHER_V1:' + 'a'.repeat(64) + ',1') => journal(value) + '\n' + journal(other);
  assert.equal(readInstalledCpuJournal(rows(valid), expected).samples, 2);
  for (const value of [valid.replace(':2:', ':3:'), valid + ':private', 'CLIQ_CPU_SAMPLE_V1:private',
    valid.replace(':5000:', ':-1:')]) assert.throws(() => readInstalledCpuJournal(rows(value), expected));
  assert.throws(() => readInstalledCpuJournal(rows(valid), { ...expected, pid: 5678 }));
  for (const value of ['CLIQ_CPU_OTHER_V1:private,1', 'CLIQ_CPU_OTHER_V1:' + 'a'.repeat(64) + ',2',
    'CLIQ_CPU_OTHER_V1:' + ['a'.repeat(64) + ',1', 'a'.repeat(64) + ',1'].join(';')])
    assert.throws(() => readInstalledCpuJournal(rows(valid, value), expected));
});
