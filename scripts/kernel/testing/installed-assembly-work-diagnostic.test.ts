// Fixed trusted-image data and real child pipes only; no native/Run or Linux qualification.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
const journal = (messages: string[]) => messages.map(MESSAGE => JSON.stringify({ _UID: '1000', _PID: '2000',
  _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n');
const emptyNumbers = Array<number>(25).fill(0);
const frame = (ordinal: number, phase: string, elapsed: number, numbers = emptyNumbers, cpu = '-:-') =>
  `CLIQ_ASSEMBLY_WORK_V1:${ordinal}:${phase}:${elapsed}:${numbers.join(':')}:${cpu}`;

test('the independent reader accepts only original-sender complete numeric prefix records, never reconstructed windows', async () => {
  const readers = await import('./installed-store-diagnostic-journal.js');
  const read = Reflect.get(readers, 'readInstalledAssemblyWorkJournal') as typeof readers.readInstalledAssemblyWorkJournal;
  assert.equal(typeof read, 'function', 'the original whole journal needs its closed independent reader');
  const rows = [frame(1, 'submit_request', 0, emptyNumbers, '30:7'),
    frame(2, 'submit_assembly_verifier_publish', 4), frame(3, 'original_store_stop', 9, emptyNumbers, '31:8')];
  const result = read(journal(rows), sender)!;
  assert.equal(result.cuts.length, 3); assert.deepEqual(result.cuts[0].process, { userCPUTime: 30, systemCPUTime: 7 });
  assert.equal(result.cuts[1].process, null); assert(Object.isFrozen(result.cuts[2].runtime.package));
  assert.equal(read(journal(['ordinary fixed service text']), sender), undefined);
  const invalid = [
    [rows[1]!], [rows[0]!, rows[0]!], [rows[0]!, rows[2]!, rows[1]!],
    [rows[0]!, 'CLIQ_ASSEMBLY_WORK_V1:truncated'], [rows[0]!.replace(':1:', ':01:')],
    [rows[0]!.replace(':submit_request:0:', ':unknown:0:')], [rows[0]! + ':0'], [rows[0]! + '\n'],
    [rows[0]!, frame(2, 'submit_assembly_policy', 1, emptyNumbers, '29:8')],
    [rows[0]!, frame(2, 'original_store_stop', 1, emptyNumbers, '-:1')],
    [frame(1, 'submit_request', 1)], [frame(1, 'submit_request', 0, [Number.MAX_SAFE_INTEGER + 1, ...emptyNumbers.slice(1)])],
    [frame(1, 'submit_request', 0, [0, 1, ...emptyNumbers.slice(2)])]
  ];
  for (const bad of invalid) assert.throws(() => read(journal(bad), sender), { code: 'ERR_ASSERTION' }, 'malformed fixed work prefix must reject');
  const foreign = JSON.parse(journal([rows[0]!])); foreign._PID = '2001';
  assert.throws(() => read(JSON.stringify(foreign), sender));
  assert.throws(() => read(journal(Array<string>(81).fill('ordinary')), sender));
  let accessed = 0;
  const bad = () => { accessed++; throw Error('private getter'); };
  assert.throws(() => read(journal(rows), Object.defineProperty({ ...sender }, 'pid', { get: bad })));
  assert.throws(() => read(journal(rows), new Proxy(sender, { get: bad, ownKeys: bad, getPrototypeOf: bad })));
  assert.equal(accessed, 0);
});

test('malformed banner packets invoke no getters and can only truncate this non-authoritative stream', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const mutations = [
    `{...row,path:'private input'}`, `{...row,phase:['submit_request']}`, `{...row,phase:'other'}`, `{...row,elapsedMs:-1}`,
    `{...row,elapsedMs:1}`, `{...row,casRead:{...row.casRead,settled:2}}`,
    `{...row,casRead:{...row.casRead,bytesRead:Number.MAX_SAFE_INTEGER+1}}`,
    `{...row,runtime:{...row.runtime,createCompare:{...row.runtime.createCompare,bytesRead:1}}}`,
    `Object.defineProperty({...row},'phase',{get:bad})`,
    `{...row,casRead:Object.defineProperty({...row.casRead},'bytesRead',{get:bad})}`,
    `new Proxy(row,{get:bad,ownKeys:bad,getPrototypeOf:bad,getOwnPropertyDescriptor:bad})`,
    `{...row,runtime:new Proxy(row.runtime,{get:bad,ownKeys:bad,getPrototypeOf:bad})}`,
    `{...row,[Symbol('private')]:1}`, `Object.defineProperty({...row},'elapsedMs',{value:0,enumerable:false})`
  ];
  for (const mutation of mutations) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
      let accessed=0;const bad=()=>{accessed++;throw Error('private getter')};
      const r={started:0,completed:0,bytesRead:0,spanElapsedMs:0},s={started:0,settled:0,spanElapsedMs:0};
      const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:r},
        casRead:{...s,bytesRead:0},publishFour:s,fileSync:s,rootSync:s};
      require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1').publish(${mutation});
      require('node:fs').writeSync(1,'accessed:'+accessed);
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
    assert.equal(child.stdout, 'accessed:0'); assert.equal(child.stderr, 'CLIQ_ASSEMBLY_WORK_V1:truncated\n');
  }
});

test('actual fragmented child output preserves numeric cuts and sampling fallback without affecting the operation', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const { readInstalledAssemblyWorkJournal: read } = await import('./installed-store-diagnostic-journal.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `
    process.argv[2]='--installed-supervisor';const fs=require('node:fs'),write=fs.writeSync;let samples=0;
    fs.writeSync=(fd,text)=>{const b=Buffer.from(text);for(let n=0;n<b.length;n+=3)write(fd,b.subarray(n,n+3));return b.length};
    process.resourceUsage=()=>{samples++;if(samples===2)throw Error('unavailable own sample');
      return {userCPUTime:30+samples,systemCPUTime:7+samples}};
  ` + banner + `
    const r={started:0,completed:0,bytesRead:0,spanElapsedMs:0},s={started:0,settled:0,spanElapsedMs:0};
    const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:r},
      casRead:{...s,bytesRead:0},publishFour:s,fileSync:s,rootSync:s};
    const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
    d.publish(row);d.publish({...row,phase:'submit_assembly_material',elapsedMs:1});
    d.publish({...row,phase:'original_store_stop',elapsedMs:2});fs.writeSync(1,'original result');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
  assert.equal(child.stdout, 'original result');
  const cuts = read(journal(child.stderr.trimEnd().split('\n')), sender)!.cuts;
  assert.deepEqual(cuts.map(cut => cut.process), [{ userCPUTime: 31, systemCPUTime: 8 }, null, { userCPUTime: 33, systemCPUTime: 10 }]);
});

test('the independent server banner is absent in credential/ordinary roles and bounds every attempted output', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  for (const role of ['--installed-credential', '--bootstrap-credential', '--ordinary']) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]=${JSON.stringify(role)};` + banner + `
      const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
      if(d.hasSubscribers)throw Error('unexpected subscription');d.publish('truncated');
    `], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
    assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
  }
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
    const m=Number.MAX_SAFE_INTEGER,r={started:m,completed:m,bytesRead:m,spanElapsedMs:m},s={started:m,settled:m,spanElapsedMs:m};
    process.resourceUsage=()=>({userCPUTime:m,systemCPUTime:m});
    const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:{...r,bytesRead:0}},
      casRead:{...s,bytesRead:m},publishFour:s,fileSync:s,rootSync:s};
    const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
    d.publish(row);d.publish({...row,phase:'submit_assembly_verifier_history',elapsedMs:m});
    d.publish({...row,phase:'original_store_stop',elapsedMs:m});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
  assert(child.stderr.endsWith('CLIQ_ASSEMBLY_WORK_V1:truncated\n'));
  assert(child.stderr.split('\n').filter(Boolean).every(row => Buffer.byteLength(row + '\n') <= 512));
  assert(Buffer.byteLength(child.stderr) <= 4096);
});

test('the server-only work banner carries bounded numeric phase cuts without private data', async () => {
  const builder = await import('./supervisor-sea-builder.js');
  const banner = Reflect.get(builder, 'INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER');
  assert.equal(typeof banner, 'string', 'the trusted server requires its independent fixed work banner');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
    const r={started:1,completed:1,bytesRead:3,spanElapsedMs:4}, s={started:2,settled:1,spanElapsedMs:5};
    const cut={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:{...r,bytesRead:0}},
      casRead:{...s,bytesRead:11},publishFour:s,fileSync:s,rootSync:s};
    require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1').publish(cut);
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null); assert.equal(child.stdout, '');
  assert.match(child.stderr, /^CLIQ_ASSEMBLY_WORK_V1:1:submit_request:0:(?:[0-9]+:){26}[0-9]+\n$/u);
  assert(Buffer.byteLength(child.stderr) <= 512);
});

test('the actual source first-submit observer, real CAS and trusted child banner round-trip without another request window', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const { readInstalledAssemblyWorkJournal: read } = await import('./installed-store-diagnostic-journal.js');
  const cas = new URL('../../../src/state/cas.ts', import.meta.url).href;
  const diagnostics = new URL('../../../src/state/installed-run-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=commonjs', '--eval',
    `process.argv[2]='--installed-supervisor';` + banner + `
    (async()=>{const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
      const {ContentAddressedStore}=await import(${JSON.stringify(cas)});
      const {beginInstalledSubmitDiagnostic,noteInstalledStoreStop}=await import(${JSON.stringify(diagnostics)});
      const root=await fs.mkdtemp(path.join(os.tmpdir(),'cliq-actual-work-'));
      try {const store=new ContentAddressedStore(root),first=beginInstalledSubmitDiagnostic();
        const ref=await store.publish(Buffer.from('hello'));await store.read(ref);await store.verify(ref);
        first.stage('submit_assembly_material');first.stage('submit_assembly_material');
        first.stage('submit_assembly_verifier_publish');
        await store.publishFour([Buffer.from('1'),Buffer.from('2'),Buffer.from('3'),Buffer.from('4')]);
        first.stage('submit_assembly_policy');
        first.stage('submit_postcommit_load');first.stage('submit_assembly_final_check');
        const second=beginInstalledSubmitDiagnostic();second?.stage('submit_assembly_final_check');
        noteInstalledStoreStop({driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:[]});
      }finally{await fs.rm(root,{recursive:true,force:true})}
    })().catch(()=>{process.exitCode=1});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536, cwd: new URL('../../..', import.meta.url) });
  assert.equal(child.error, undefined); assert.equal(child.status, 0, child.stderr); assert.equal(child.signal, null);
  const cuts = read(journal(child.stderr.trimEnd().split('\n')), sender)!.cuts;
  assert.deepEqual(cuts.map(cut => cut.phase), ['submit_request', 'submit_assembly_material', 'submit_assembly_verifier_publish', 'submit_assembly_policy']);
  assert.equal(cuts[1]!.casRead.bytesRead, 10); assert.equal(cuts[1]!.casRead.settled, 2);
  assert.equal(cuts[3]!.publishFour.settled, 1); assert.equal(cuts[3]!.fileSync.settled, 5); assert.equal(cuts[3]!.rootSync.settled, 8);
  assert.equal(child.stdout, '');
});

test('the fixed four-KiB output bound includes its final explicit truncation record', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const { INSTALLED_ASSEMBLY_WORK_PHASES: phases } = await import('../../../src/state/installed-work-diagnostics.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
    const m=99999999999999,r={started:m,completed:m,bytesRead:m,spanElapsedMs:m},s={started:m,settled:m,spanElapsedMs:m};
    process.resourceUsage=()=>({userCPUTime:999999999999,systemCPUTime:999999999999});
    const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:{...r,bytesRead:0}},
      casRead:{...s,bytesRead:m},publishFour:s,fileSync:s,rootSync:s};
    const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
    for(const [index,phase] of ${JSON.stringify(phases)}.entries())d.publish({...row,phase,elapsedMs:index===0?0:m});
    d.publish({...row,phase:'original_store_stop',elapsedMs:m});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert(child.stderr.endsWith('CLIQ_ASSEMBLY_WORK_V1:truncated\n'));
  assert(Buffer.byteLength(child.stderr) <= 4096, 'all measurement records including truncation must obey the existing four-KiB bound');
});
