import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { build } from 'esbuild';
import ts from 'typescript';

test('a real diagnostic sink failure cannot skip original retirement or replace its original error', () => {
  // Exact driver control flow with real EBADF and real descriptor closes. This
  // data-only composition creates no installed client, native proof or grant.
  const source = readFileSync(fileURLToPath(new URL('./installed-control-client-driver.ts', import.meta.url)), 'utf8');
  const phases = source.slice(source.indexOf('let phase:'), source.indexOf('\nconst sameFile'));
  const main = source.slice(source.indexOf('async function main()'), source.indexOf('\ntry { await main(); }'));
  const ending = source.slice(source.indexOf('try { await main(); }'));
  assert(phases.startsWith('let phase:') && main.startsWith('async function main()') && ending.startsWith('try { await main(); }'));
  const code = ts.transpileModule(`(async()=>{${phases}\n${main}
    const originalMain=main;main=async()=>{try{await originalMain()}catch(error){observeFailure(error);throw error}};
    ${ending}\nreturn {phase,failedPhase};})()`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  for (const mode of ['success', 'business_failure', 'retirement_failure']) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';import vm from 'node:vm';
      import {openSync,closeSync,fstatSync,writeSync} from 'node:fs';
      const mode=${JSON.stringify(mode)},events=[],clientFd=openSync('/dev/null','r'),selectedFd=openSync('/dev/null','r');
      const business=new Error('original business failure'),retirement=new Error('original retirement failure');
      const joined=fd=>{try{fstatSync(fd);return false}catch(error){assert.equal(error.code,'EBADF');return true}};
      let originalFailure='none',exitCode=0,escaped=false;
      const context={assert,writeSync,ResourceRetirementError:class extends Error{},
        observeFailure(error){originalFailure=error===business?'business':error===retirement?'retirement':'other'},
        process:{platform:'linux',arch:'x64',geteuid:()=>1001,getegid:()=>1001,argv:['node','driver','data-only'],
          once(){},removeListener(){events.push('remove-listener')},stdin:{destroy(){}},stdout:{on(){},removeListener(){events.push('remove-listener')}},
          stderr:{write(bytes){writeSync(2,bytes);return true}},set exitCode(value){exitCode=value}},
        fixtureComposition:async()=>({stateRoot:'data-only',releaseKeys:[]}),
        createInstalledRuntime:()=>({openSelected:async()=>({close:async()=>{events.push('selected-close');closeSync(selectedFd)}})}),
        openInstalledSupervisorClient:async()=>({hello:{},close:async()=>{events.push('client-close');closeSync(clientFd);if(mode==='retirement_failure')throw retirement}}),
        output:async()=>{},requests:async function*(){closeSync(2);if(mode==='business_failure')throw business}};
      try{await vm.runInNewContext(${JSON.stringify(code)},context)}catch{escaped=true}
      const report={escaped,originalFailure,exitCode,events,clientJoined:joined(clientFd),selectedJoined:joined(selectedFd)};
      if(!report.clientJoined)closeSync(clientFd);if(!report.selectedJoined)closeSync(selectedFd);
      console.log(JSON.stringify(report));
    `], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { escaped: false, originalFailure: mode === 'success' ? 'none' : mode === 'business_failure' ? 'business' : 'retirement',
      exitCode: mode === 'success' ? 0 : 1, events: mode === 'retirement_failure'
        ? ['client-close', 'remove-listener', 'remove-listener', 'remove-listener']
        : ['client-close', 'selected-close', 'remove-listener', 'remove-listener', 'remove-listener'],
      clientJoined: true, selectedJoined: mode !== 'retirement_failure' });
  }
});

test('installed client driver refuses an unowned composition without reflecting supplied input', () => {
  const driver = fileURLToPath(new URL('./installed-control-client-driver.ts', import.meta.url));
  const result = spawnSync(process.execPath, ['--import', 'tsx', driver,
    '/var/tmp/owned-untrusted-diagnostic-sentinel/ownership-ledger.json'], {
    input: '{"apiKey":"owned-untrusted-diagnostic-sentinel"}\n', timeout: 10_000,
    env: { PATH: '/usr/bin:/bin', NODE_NO_WARNINGS: '1' }, encoding: 'utf8'
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, process.platform === 'linux' && process.arch === 'x64'
    ? 'installed control client driver progress phase=platform\ninstalled control client driver progress phase=composition\ninstalled control client driver failed phase=composition\n'
    : 'installed control client driver progress phase=platform\ninstalled control client driver failed phase=platform\n');
});

test('installed client driver bundles as one ordinary Node consumer with no external application loader', async () => {
  const result = await build({ entryPoints: [fileURLToPath(new URL('./installed-control-client-driver.ts', import.meta.url))],
    outfile: 'installed-control-client-driver.mjs', bundle: true, platform: 'node', format: 'esm', target: 'node22.13',
    metafile: true, write: false });
  assert.equal(result.outputFiles?.length, 1);
  assert(result.outputFiles[0]!.contents.length > 0 && result.outputFiles[0]!.contents.length <= 16 * 1024 * 1024);
  assert(Object.values(result.metafile!.outputs).flatMap(output => output.imports).every(item => item.external && item.path.startsWith('node:')));
});
