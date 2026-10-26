import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { build } from 'esbuild';
import ts from 'typescript';
import { installedClientBuildOptions } from './installed-client-build.js';

test('each original auth phase samples actual self resource usage once, with inert V1 fallback when unavailable', () => {
  // Exact source-owned subscriber and real child stderr, not an installed
  // Supervisor, native authentication proof or injected execution authority.
  const source = readFileSync(new URL('./installed-control-client-driver.ts', import.meta.url), 'utf8');
  const block = source.slice(source.indexOf('function observeAuthentication()'), source.indexOf('\nconst sameFile'));
  assert(block.startsWith('function observeAuthentication()'));
  const code = ts.transpileModule(block, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  for (const mode of ['actual', 'unavailable', 'invalid']) {
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
      import assert from 'node:assert/strict';import {channel} from 'node:diagnostics_channel';
      import {writeSync} from 'node:fs';import {resourceUsage} from 'node:process';
      const {copyInstalledClientAuthenticationWork,copyInstalledClientAuthenticationProcess,installedClientAuthenticationMarker}=
        await import(${JSON.stringify(new URL('./installed-client-consumer.ts', import.meta.url).href)});
      const {INSTALLED_CLIENT_PHASE_CHANNEL,INSTALLED_CLIENT_PHASES}=
        await import(${JSON.stringify(new URL('../../../src/state/installed-diagnostics.ts', import.meta.url).href)});
      const {INSTALLED_WORK_CHANNEL}=await import(${JSON.stringify(new URL('../../../src/state/installed-work-diagnostics.ts', import.meta.url).href)});
      let calls=0,snapshot=null;const mode=${JSON.stringify(mode)};
      const ownProcess={resourceUsage(){calls++;if(mode==='unavailable')throw new Error('owned unavailable measurement');
        if(mode==='invalid')return {userCPUTime:-1,systemCPUTime:0,fsRead:0,fsWrite:0};
        const {userCPUTime,systemCPUTime,fsRead,fsWrite}=resourceUsage();
        return snapshot={userCPUTime,systemCPUTime,fsRead,fsWrite};}};
      const observe=new Function('channel','performance','INSTALLED_WORK_CHANNEL','INSTALLED_CLIENT_PHASE_CHANNEL',
        'INSTALLED_CLIENT_PHASES','copyInstalledClientAuthenticationWork','copyInstalledClientAuthenticationProcess',
        'installedClientAuthenticationMarker','writeSync','process',${JSON.stringify(code + ';return observeAuthentication;')})(
          channel,performance,INSTALLED_WORK_CHANNEL,INSTALLED_CLIENT_PHASE_CHANNEL,INSTALLED_CLIENT_PHASES,
          copyInstalledClientAuthenticationWork,copyInstalledClientAuthenticationProcess,installedClientAuthenticationMarker,writeSync,ownProcess);
      const stop=observe();channel(INSTALLED_CLIENT_PHASE_CHANNEL).publish('native_connected');
      channel(INSTALLED_CLIENT_PHASE_CHANNEL).publish('native_connected');stop();
      assert.equal(calls,1);console.log(JSON.stringify({calls,snapshot}));
    `], { encoding: 'utf8', timeout: 10000,
      // This data-only child loads the source via tsx. Node 26's unrelated
      // loader deprecation is not a driver marker; actual driver argv/env and
      // the consumer's strict stderr scanner are deliberately unchanged.
      env: { ...process.env, NODE_NO_WARNINGS: '1' } });
    assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout); assert.equal(report.calls, 1);
    const prefix = mode === 'actual' ? 'CLIQ_INSTALLED_CLIENT_AUTH_V2:self_whole_process_cumulative:' : 'CLIQ_INSTALLED_CLIENT_AUTH_V1:';
    assert(result.stderr.startsWith(prefix + 'native_connected:')); assert.equal(result.stderr.split('\n').length, 2);
    const fields = result.stderr.slice(prefix.length).trimEnd().split(':');
    assert.match(fields[1]!, /^(0|[1-9][0-9]*)$/u); assert.equal(fields[2], 'none');
    assert.deepEqual(fields.slice(3).map(Number), mode === 'actual'
      ? [report.snapshot.userCPUTime, report.snapshot.systemCPUTime, report.snapshot.fsRead, report.snapshot.fsWrite] : []);
  }
});

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
    // Only this data-only child deliberately closes fd2; suppress its loader's
    // unrelated warning after that close. Qualification driver argv is unchanged.
    const result = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=module', '-e', `
      import assert from 'node:assert/strict';import vm from 'node:vm';
      import {channel} from 'node:diagnostics_channel';
      import {openSync,closeSync,fstatSync,writeSync} from 'node:fs';
      const {copyInstalledClientAuthenticationWork,installedClientAuthenticationMarker}=await import(${JSON.stringify(new URL('./installed-client-consumer.ts', import.meta.url).href)});
      const {INSTALLED_CLIENT_PHASE_CHANNEL,INSTALLED_CLIENT_PHASES}=await import(${JSON.stringify(new URL('../../../src/state/installed-diagnostics.ts', import.meta.url).href)});
      const {INSTALLED_WORK_CHANNEL}=await import(${JSON.stringify(new URL('../../../src/state/installed-work-diagnostics.ts', import.meta.url).href)});
      const {runInstalledControlJsonl}=await import(${JSON.stringify(new URL('../../../src/control/installed-jsonl.ts', import.meta.url).href)});
       const {classifyInstalledRequestError,observeInstalledRequestFailures}=await import(${JSON.stringify(new URL('../../../src/state/installed-request-diagnostics.ts', import.meta.url).href)});
       const {installedRequestFailureMarker}=await import(${JSON.stringify(new URL('./installed-client-request-failure.ts', import.meta.url).href)});
      const mode=${JSON.stringify(mode)},events=[],clientFd=openSync('/dev/null','r'),selectedFd=openSync('/dev/null','r');
      const business=new Error('original business failure'),retirement=new Error('original retirement failure');
      const joined=fd=>{try{fstatSync(fd);return false}catch(error){assert.equal(error.code,'EBADF');return true}};
      let originalFailure='none',exitCode=0,escaped=false;
      const context={assert,writeSync,performance,channel,INSTALLED_CLIENT_PHASE_CHANNEL,INSTALLED_CLIENT_PHASES,
        INSTALLED_WORK_CHANNEL,copyInstalledClientAuthenticationWork,installedClientAuthenticationMarker,runInstalledControlJsonl,ResourceRetirementError:class extends Error{},
         classifyInstalledRequestError,observeInstalledRequestFailures,installedRequestFailureMarker,
        observeFailure(error){originalFailure=error===business?'business':error===retirement?'retirement':'other'},
        process:{platform:'linux',arch:'x64',geteuid:()=>1001,getegid:()=>1001,argv:['node','driver','data-only'],
          once(){},removeListener(){events.push('remove-listener')},stdin:{destroy(){}},stdout:{on(){},removeListener(){events.push('remove-listener')}},
          stderr:{write(bytes){writeSync(2,bytes);return true}},set exitCode(value){exitCode=value}},
        fixtureComposition:async()=>({stateRoot:'data-only',releaseKeys:[]}),
        createInstalledRuntime:()=>({openSelected:async()=>({close:async()=>{events.push('selected-close');closeSync(selectedFd)}})}),
        openInstalledSupervisorClient:async()=>({hello:{method:'control.hello',protocolVersion:1,serverBuild:'data-only',
          controlSchemaRange:{min:1,max:1},headlessSchemaRange:{min:1,max:1},enabledFeatureIds:[],supervisorInstanceId:'data-only',
          activeRuntimeBundle:{schemaVersion:1,runtimeBundleRef:'a'.repeat(64),bundleDigest:'a'.repeat(64),bundleVersion:'1'}},
          close:async()=>{events.push('client-close');closeSync(clientFd);if(mode==='retirement_failure')throw retirement}}),
        output:async()=>{},requests:async function*(){closeSync(2);
          channel(INSTALLED_WORK_CHANNEL).publish(Object.defineProperty({},'package',{get(){throw new Error('diagnostic getter')}}));
          channel(INSTALLED_CLIENT_PHASE_CHANNEL).publish('final_current_verified');
          if(mode==='business_failure')throw business}};
      try{await vm.runInNewContext(${JSON.stringify(code)},context)}catch{escaped=true}
      const report={escaped,originalFailure,exitCode,events,clientJoined:joined(clientFd),selectedJoined:joined(selectedFd)};
      if(!report.clientJoined)closeSync(clientFd);if(!report.selectedJoined)closeSync(selectedFd);
      console.log(JSON.stringify(report));
    `], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stdout);
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
    metafile: true, write: false, ...installedClientBuildOptions() });
  assert.equal(result.outputFiles?.length, 1);
  assert(result.outputFiles[0]!.contents.length > 0 && result.outputFiles[0]!.contents.length <= 16 * 1024 * 1024);
  assert(Object.values(result.metafile!.outputs).flatMap(output => output.imports).every(item => item.external && item.path.startsWith('node:')));
  const inputs = Object.keys(result.metafile!.inputs);
  for (const entry of ['entry.ts', 'application.ts', 'tui.tsx'])
    assert(inputs.some(name => name.endsWith('src/client/' + entry)), 'the fixed client image must include each real application surface');
  assert(inputs.some(name => name.endsWith('src/control/installed-jsonl.ts')),
    'the real installed driver must consume the production JSONL adapter');
  assert(inputs.some(name => name.endsWith('src/control/v1.ts')),
    'the real installed driver and client must consume the same generated contract');
  assert(inputs.some(name => name.endsWith('src/headless/installed.ts')),
    'the schema3 installed driver must consume the production headless adapter');
  assert(inputs.some(name => name.endsWith('src/control/session.ts')),
    'the schema3 installed driver must consume the shared control session');
});

test('the campaign wrapper alone retains the original 1024 frames including automatic hello', async () => {
  const source = readFileSync(new URL('./installed-control-client-driver.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('driver.ts', source, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find(statement => ts.isFunctionDeclaration(statement) && statement.name?.text === 'requests');
  assert(declaration && ts.isFunctionDeclaration(declaration));
  const emitted = ts.transpileModule(declaration.getText(parsed), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const frame = Buffer.from('{"method":"supervisor.status","protocolVersion":1}\n');
  for (const count of [1023, 1024]) {
    const input = async function* () { yield Buffer.concat(Array.from({ length: count }, () => frame)); };
    const requests = new Function('process', 'assert', emitted + ';return requests;')({ stdin: input() }, assert) as () => AsyncIterable<Buffer>;
    let frames = 0;
    const collect = async () => { for await (const bytes of requests()) { frames++; assert(bytes.equals(frame)); } };
    if (count === 1023) await collect();
    else await assert.rejects(collect(), { name: 'AssertionError' });
    assert.equal(frames, 1023, 'a wrapper failure may not dispatch the 1024th business request');
  }
});
