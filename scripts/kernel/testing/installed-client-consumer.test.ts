// Actual child-process JSONL transport only. These fixtures do not impersonate
// an installed Supervisor or qualify native authentication/execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { InstalledClientConsumerDeadlineError, InstalledClientDriverError, openInstalledClientConsumer,
  copyInstalledClientAuthenticationWork, copyInstalledClientAuthenticationProcess,
  installedClientAuthenticationMarker } from './installed-client-consumer.js';

for (const mode of ['jsonl', 'rpc'] as const) test(`schema3 ${mode} actual adapter and scanned child consumer drain all pages and records before response join`, async () => {
  const sessionUrl = new URL('../../../src/control/session.ts', import.meta.url).href;
  const adapterUrl = new URL('../../../src/headless/installed.ts', import.meta.url).href;
  const source = `import assert from 'node:assert/strict';
    import {createInstalledControlSession} from ${JSON.stringify(sessionUrl)};
    import {runInstalledHeadlessJsonl,runInstalledHeadlessRpc} from ${JSON.stringify(adapterUrl)};
    const at='2026-10-25T00:00:00.000Z',ref='a'.repeat(64),cursors=[];
    const snapshot={schemaVersion:1,operation:'agent',latestRunItemSeq:0,run:{id:'run',sessionId:'session',specRef:ref,
      status:'queued',nextStep:'agent',frontierRef:ref,revision:1,leaseEpoch:0,latestCheckpointId:'checkpoint',
      budgetReserved:{modelTokens:0,costMicros:0,toolCalls:0,repairAttempts:0},budgetConsumed:{modelTokens:0,costMicros:0,toolCalls:0,repairAttempts:0},
      repairCount:0,cancelRequested:false,createdAt:at,updatedAt:at,deadlineAt:'2026-10-25T01:00:00.000Z'}};
    let closes=0;const session=createInstalledControlSession({hello:{method:'control.hello',protocolVersion:1,serverBuild:'inert',
      controlSchemaRange:{min:1,max:1},headlessSchemaRange:{min:3,max:3},enabledFeatureIds:['run.attach'],supervisorInstanceId:'inert',
      activeRuntimeBundle:{schemaVersion:1,runtimeBundleRef:ref,bundleDigest:ref,bundleVersion:'1'}},
      close:async()=>{closes++},'run.attach':async request=>{cursors.push(request.afterEventSeq);assert(cursors.length<=3);const n=request.afterEventSeq+1,high=cursors.length===1?3:99;
        return {protocolVersion:1,ok:true,result:{method:'run.attach',snapshot,earliestRetainedEventSeq:1,latestRetainedEventSeq:high,
          highWaterEventSeq:high,nextEventSeq:n,events:[{schemaVersion:1,kind:'progress',runId:'run',eventSeq:n,
            observedRunRevision:1,phase:'agent',occurredAt:at}]}}}});
    await ${mode === 'rpc' ? 'runInstalledHeadlessRpc' : 'runInstalledHeadlessJsonl'}(session,process.stdin,bytes=>new Promise((resolve,reject)=>process.stdout.write(bytes,e=>e?reject(e):resolve())));
    await session.close();assert.equal(closes,1);assert.deepEqual(cursors,[0,1,2]);`;
  const scans: Buffer[] = []; let closed = 0, joined = 0;
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--import', 'tsx', '--input-type=module', '-e', source], cwd: process.cwd(),
    // Suppress only this source-loader fixture's unrelated Node26 warning;
    // genuine installed driver argv/env and strict stderr rules stay unchanged.
    env: { ...process.env, NODE_NO_WARNINGS: '1' }, headlessSchemaVersion: 3,
    ...(mode === 'rpc' ? { headlessTransport: 'rpc' as const } : {}),
    openScan: () => ({ scan(bytes) { scans.push(Buffer.from(bytes)); }, close() { closed++; } }), onJoined() { joined++; } });
  const response = await client.send({ protocolVersion: 1, method: 'run.attach', runId: 'run', afterEventSeq: 0, limit: 1 });
  assert.equal(response.result?.nextEventSeq, 3); await client.close();
  assert.equal(joined, 1); assert.equal(closed, 2);
  const wire = Buffer.concat(scans).toString('utf8').trim().split('\n').map(text => parseJsonStrict(text)) as Record<string, any>[];
  const original = mode === 'rpc' ? wire.at(-1)!.result.response
    : wire.filter(record => record.type === 'response').at(-1)!.response;
  assert.equal(Object.getPrototypeOf(client.hello), null, 'hello retains its original strict-parser representation');
  assert.equal(Object.getPrototypeOf(response), null, 'a validated response retains its original wire object');
  assert.deepEqual(response, original, 'cross-transport replay compares the complete original wire data');
  const output = Buffer.concat(scans).toString('utf8').trim().split('\n').map(text => JSON.parse(text));
  assert.equal(output.length, mode === 'rpc' ? 8 : 7);
  const records = mode === 'rpc' ? output.filter(value => value.method === 'control.record').map(value => {
    assert.equal(value.params.id, 1); return value.params.record;
  }) : output;
  assert.deepEqual(records.filter(record => record.type === 'progress').map(record => record.eventSeq), [1, 2, 3]);
  assert.equal(response.result?.highWaterEventSeq, 99, 'the later page retains its actual newer high-water without chasing it');
  if (mode === 'rpc') assert.equal(output.filter(value => value.id === 1).length, 1);
});

const protocol = `import {createInterface} from 'node:readline';
const emit=v=>process.stdout.write(JSON.stringify(v)+'\\n');
emit({ok:true,protocolVersion:1,result:{method:'control.hello',supervisorInstanceId:'owned-framing-fixture'}});
let count=0;for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
const request=JSON.parse(line);++count;
if(request.delay)await new Promise(r=>setTimeout(r,request.delay));
if(request.invalid)process.stdout.write('{"protocolVersion":1,"ok":true}\\n');
else emit({ok:true,protocolVersion:1,result:{count,method:request.method}});
}
await new Promise(r=>setTimeout(r,20));`;

for (const mode of ['wrong_id', 'missing_attach_records'] as const) test(`schema3 RPC scanned consumer rejects ${mode} and still joins both original pipes`, async () => {
  const hello = { method: 'control.hello', protocolVersion: 1, serverBuild: 'inert', controlSchemaRange: { min: 1, max: 1 },
    headlessSchemaRange: { min: 3, max: 3 }, enabledFeatureIds: ['supervisor.status', 'run.attach'], supervisorInstanceId: 'inert',
    activeRuntimeBundle: { schemaVersion: 1, runtimeBundleRef: 'a'.repeat(64), bundleDigest: 'a'.repeat(64), bundleVersion: '1' } };
  const source = `import {createInterface} from 'node:readline';
    const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':
      '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
    const emit=(id,response)=>process.stdout.write(canonical({jsonrpc:'2.0',id,result:{schemaVersion:3,protocolVersion:1,type:'response',response}})+'\\n');
    let count=0;for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
      const request=JSON.parse(line);if(++count===1)emit(0,{protocolVersion:1,ok:true,result:${JSON.stringify(hello)}});
      else emit(${mode === 'wrong_id' ? 'request.id+1' : 'request.id'},{protocolVersion:1,ok:false,method:request.method,
        error:{schemaVersion:1,code:'AUTHORIZATION_REQUIRED',retryable:false,messageCode:'inert'}});
    }`;
  let closed = 0, joined = 0;
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', source], cwd: process.cwd(), env: process.env,
    headlessSchemaVersion: 3, headlessTransport: 'rpc',
    openScan: () => ({ scan() {}, close() { closed++; } }), onJoined() { joined++; } });
  await assert.rejects(client.send(mode === 'wrong_id' ? { protocolVersion: 1, method: 'supervisor.status' }
    : { protocolVersion: 1, method: 'run.attach', runId: 'run', afterEventSeq: 0 }));
  await assert.rejects(client.close()); assert.equal(closed, 2); assert.equal(joined, 0);
});

async function fixture(progress = false) {
  const scans: Buffer[] = []; let opened = 0, closed = 0, joined = 0;
  const authentication = ['manager_observer_loaded', 'initial_current_observed', 'native_connected', 'pre_hello_current_verified',
    'hello_exchange_started', 'hello_received', 'final_current_verified']
    .map((stage, index) => `CLIQ_INSTALLED_CLIENT_AUTH_V1:${stage}:${index}:none\n`).join('');
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', progress ? `process.stderr.write('installed control client driver progress phase=authentication\\n');
      process.stderr.write(${JSON.stringify(authentication)});\n${protocol}\nprocess.stderr.write('installed control client driver progress phase=retirement\\n');` : protocol],
    cwd: process.cwd(), env: process.env,
    openScan() { opened++; let retired = false; return {
      scan(bytes) { assert(!retired); scans.push(Buffer.from(bytes)); },
      close() { assert(!retired); retired = true; closed++; }
    }; }, onJoined() { joined++; } });
  return { client, counts: () => ({ opened, closed, joined }), scans };
}

test('the genuine-driver consumer joins real EOF, pipes and process after independent canonical responses', async () => {
  const { client, counts, scans } = await fixture();
  assert.equal(client.supervisorInstanceId, 'owned-framing-fixture');
  assert.equal((await client.send({ protocolVersion: 1, method: 'run.get' })).result?.count, 1);
  assert.equal((await client.send({ protocolVersion: 1, method: 'run.attach' })).result?.count, 2);
  assert.deepEqual(counts(), { opened: 2, closed: 0, joined: 0 });
  await client.close(); await client.close();
  assert.deepEqual(counts(), { opened: 2, closed: 2, joined: 1 });
  assert(Buffer.concat(scans).includes(Buffer.from('control.hello')));
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.get' }));
});

test('schema3 consumer scans and decodes the real JSONL wrapper without weakening original process join', async () => {
  const hello = { method: 'control.hello', protocolVersion: 1, serverBuild: 'inert', controlSchemaRange: { min: 1, max: 1 },
    headlessSchemaRange: { min: 3, max: 3 }, enabledFeatureIds: ['supervisor.status'], supervisorInstanceId: 'inert',
    activeRuntimeBundle: { schemaVersion: 1, runtimeBundleRef: 'a'.repeat(64), bundleDigest: 'a'.repeat(64), bundleVersion: '1' } };
  const scans: Buffer[] = []; let closed = 0, joined = 0;
  const script = `import assert from 'node:assert/strict';import {createInterface} from 'node:readline';
    const j=v=>JSON.stringify(v,Object.keys(v).sort());
    const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':
      '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
    const emit=response=>process.stdout.write(canonical({schemaVersion:3,protocolVersion:1,type:'response',response})+'\\n');
    emit({protocolVersion:1,ok:true,result:${JSON.stringify(hello)}});
    for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
      const outer=JSON.parse(line);assert.deepEqual(Object.keys(outer).sort(),['request','schemaVersion']);assert.equal(outer.schemaVersion,3);
      assert.deepEqual(outer.request,{protocolVersion:1,method:'supervisor.status'});
      emit({protocolVersion:1,ok:false,method:'supervisor.status',error:{schemaVersion:1,code:'AUTHORIZATION_REQUIRED',retryable:false,messageCode:'inert'}});
    }`;
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', script], cwd: process.cwd(), env: process.env, headlessSchemaVersion: 3,
    openScan: () => ({ scan(bytes) { scans.push(Buffer.from(bytes)); }, close() { closed++; } }), onJoined() { joined++; } });
  assert.equal(client.hello.headlessSchemaRange.min, 3);
  const response = await client.send({ protocolVersion: 1, method: 'supervisor.status' });
  assert.equal(response.ok, false); assert.equal(response.error?.code, 'AUTHORIZATION_REQUIRED');
  await client.close(); assert.equal(joined, 1); assert.equal(closed, 2);
  assert(Buffer.concat(scans).includes(Buffer.from('"schemaVersion":3')));
});

test('the genuine-driver consumer counts automatic hello and never sends frame 1025', async () => {
  const { client, scans } = await fixture(true);
  for (let count = 1; count <= 1023; count++) {
    assert.equal((await client.send({ protocolVersion: 1, method: 'run.get' })).result?.count, count);
  }
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await client.close();
  const bytes = Buffer.concat(scans);
  assert(bytes.includes(Buffer.from('installed control client driver progress phase=authentication\n')));
  assert(bytes.includes(Buffer.from('installed control client driver progress phase=retirement\n')));
  assert.equal(bytes.toString().split('CLIQ_INSTALLED_CLIENT_AUTH_V1:').length - 1, 7);
});

test('the genuine-driver consumer rejects overlapping sends and makes a malformed response sticky', async () => {
  const { client } = await fixture();
  const first = client.send({ protocolVersion: 1, method: 'run.get', delay: 30 });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  assert.equal((await first).result?.count, 1);
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.get', invalid: true }));
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await assert.rejects(client.close());
});

test('the genuine-driver consumer never retries after its original request deadline', async () => {
  const { client, counts } = await fixture();
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit', delay: 40 }, 5), error => {
    assert(error instanceof InstalledClientConsumerDeadlineError);
    assert.deepEqual(Object.keys(error.diagnostic).sort(), ['elapsedMs', 'frames', 'kind', 'originalDeadlineMs', 'stage']);
    assert.equal(error.diagnostic.kind, 'installed_client_deadline'); assert.equal(error.diagnostic.stage, 'request');
    assert.equal(error.diagnostic.originalDeadlineMs, 5); assert.equal(error.diagnostic.frames, 1);
    assert(Number.isSafeInteger(error.diagnostic.elapsedMs) && error.diagnostic.elapsedMs >= 0);
    return true;
  });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await assert.rejects(client.close());
  assert.deepEqual(counts(), { opened: 2, closed: 2, joined: 0 });
});

test('the genuine-driver consumer retains only the fixed driver failure stage and still joins its child', async () => {
  let closed = 0, joined = false;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['-e', "process.stderr.write('installed control client driver failed phase=selection\\n');process.exitCode=1"],
    cwd: process.cwd(), env: process.env,
    openScan: () => ({ scan() {}, close() { closed++; } }), onJoined() { joined = true; }
  }), error => {
    assert(error instanceof InstalledClientDriverError);
    assert.deepEqual(error.diagnostic, { kind: 'installed_client_driver', stage: 'selection' });
    assert(!error.message.includes('apiKey')); return true;
  });
  assert.equal(closed, 2); assert.equal(joined, false);
});

for (const withProcess of [false, true]) test(`a real failed child retains its scanned authentication prefix${withProcess ? ' with whole-process counters' : ''} without replacing failure or claiming readiness`, async () => {
  const work = { package: { started: 1, completed: 1, bytesRead: 10, spanElapsedMs: 2 },
    revalidate: { started: 2, completed: 2, bytesRead: 20, spanElapsedMs: 3 },
    createCompare: { started: 0, completed: 0, bytesRead: 0, spanElapsedMs: 0 } };
  const own = { userCPUTime: 100, systemCPUTime: 20, fsRead: 3, fsWrite: 4 };
  const markers = Buffer.concat([installedClientAuthenticationMarker('manager_observer_loaded', 1, work, withProcess ? own : undefined),
    installedClientAuthenticationMarker('initial_current_observed', 2, work, withProcess ? own : undefined)]);
  const scanned: Buffer[] = []; let opened = 0, closed = 0, joined = false;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `process.stderr.write('installed control client driver progress phase=authentication\\n');
      const bytes=Buffer.from(${JSON.stringify(markers.toString('base64'))},'base64');process.stderr.write(bytes.subarray(0,19));
      await new Promise(r=>setImmediate(r));process.stderr.write(bytes.subarray(19));
      process.stderr.write('installed control client driver failed phase=authentication\\n');process.exitCode=1;`],
    cwd: process.cwd(), env: process.env,
    openScan() { opened++; return { scan(bytes) { scanned.push(Buffer.from(bytes)); }, close() { closed++; } }; },
    onJoined() { joined = true; }
  }), error => {
    assert(error instanceof InstalledClientDriverError);
    assert.equal(error.diagnostic.kind, 'installed_client_driver'); assert.equal(error.diagnostic.stage, 'authentication');
    const rows = error.diagnostic.authentication; assert.equal(rows?.length, 2); assert(rows);
    assert.deepEqual(rows.map(({ stage, elapsedMs, work: actualWork, process }) => ({ stage, elapsedMs, work: actualWork, process })),
      ['manager_observer_loaded', 'initial_current_observed'].map((stage, index) => ({ stage, elapsedMs: index + 1, work,
        process: withProcess ? own : undefined })));
    assert(rows.every(row => Number.isSafeInteger(row.observedElapsedMs) && row.observedElapsedMs >= 0));
    assert(Object.isFrozen(rows) && rows.every(row => Object.isFrozen(row) && Object.isFrozen(row.work)));
    assert(!Object.hasOwn(error.diagnostic, 'qualified') && !Object.hasOwn(error.diagnostic, 'frames'));
    return true;
  });
  assert.equal(opened, 2); assert.equal(closed, 2); assert.equal(joined, false);
  assert(Buffer.concat(scanned).includes(markers), 'all original split marker bytes were scanned before diagnosis');
});

test('the original ready deadline retains the last scanned split progress marker without extending its budget', async () => {
  const scanned: Buffer[] = []; let closed = 0, joined = false;
  const started = performance.now();
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `
      process.stderr.write('installed control client driver progress phase=selection\\ninstalled control client driver prog');
      await new Promise(resolve=>setTimeout(resolve,10));
      process.stderr.write('ress phase=authentication\\n');
      for await (const _ of process.stdin) { /* join the original EOF */ }
    `], cwd: process.cwd(), env: process.env, timeout: 500,
    openScan: () => ({ scan(bytes) { scanned.push(Buffer.from(bytes)); }, close() { closed++; } }),
    onJoined() { joined = true; }
  }), error => {
    assert(error instanceof InstalledClientConsumerDeadlineError);
    assert.deepEqual(Object.keys(error.diagnostic).sort(),
      ['elapsedMs', 'frames', 'kind', 'lastObservedDriverStage', 'originalDeadlineMs', 'stage']);
    assert.equal(error.diagnostic.stage, 'ready'); assert.equal(error.diagnostic.originalDeadlineMs, 500);
    assert.equal(error.diagnostic.frames, 0); assert.equal(error.diagnostic.lastObservedDriverStage, 'authentication');
    return true;
  });
  assert(performance.now() - started < 2000);
  assert.equal(Buffer.concat(scanned).toString(),
    'installed control client driver progress phase=selection\ninstalled control client driver progress phase=authentication\n');
  assert.equal(closed, 2); assert.equal(joined, false);
});

test('the ready deadline retains scanned split authentication boundaries and actual work counters only as diagnostics', async () => {
  const marker = 'CLIQ_INSTALLED_CLIENT_AUTH_V1:hello_exchange_started:12:1:1:10:3:2:2:20:4:0:0:0:0\n';
  const scanned: Buffer[] = []; let closed = 0;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `process.stderr.write(${JSON.stringify(marker.slice(0, 33))});
      await new Promise(r=>setTimeout(r,10));process.stderr.write(${JSON.stringify(marker.slice(33))});
      for await(const _ of process.stdin){}`], cwd: process.cwd(), env: process.env, timeout: 500,
    openScan: () => ({ scan(bytes) { scanned.push(Buffer.from(bytes)); }, close() { closed++; } }), onJoined() { assert.fail(); }
  }), error => {
    assert(error instanceof InstalledClientConsumerDeadlineError);
    assert.equal(error.diagnostic.originalDeadlineMs, 500); assert.equal(error.diagnostic.frames, 0);
    const rows = error.diagnostic.authentication; assert.equal(rows?.length, 1);
    assert.equal(rows[0]?.stage, 'hello_exchange_started'); assert.equal(rows[0]?.elapsedMs, 12);
    assert(Number.isSafeInteger(rows[0]?.observedElapsedMs) && rows[0]!.observedElapsedMs >= 0);
    assert.deepEqual(rows[0]?.work, { package: { started: 1, completed: 1, bytesRead: 10, spanElapsedMs: 3 },
      revalidate: { started: 2, completed: 2, bytesRead: 20, spanElapsedMs: 4 },
      createCompare: { started: 0, completed: 0, bytesRead: 0, spanElapsedMs: 0 } });
    assert(Object.isFrozen(rows) && Object.isFrozen(rows[0]) && Object.isFrozen(rows[0]?.work)); return true;
  });
  assert.equal(Buffer.concat(scanned).toString(), marker); assert.equal(closed, 2);
});

test('only primitive fixed driver stages can enter deadline observations without invoking getters', () => {
  let accessed = false;
  const getter = Object.defineProperty({}, 'toString', { get() { accessed = true; throw new Error('untrusted getter'); } });
  for (const stage of [null, {}, getter, new String('authentication'), 'unknown-stage']) {
    assert.throws(() => new InstalledClientDriverError(stage as never), assert.AssertionError);
    assert.throws(() => new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, stage as never), assert.AssertionError);
  }
  assert.equal(accessed, false);
  for (const stage of ['platform', 'composition', 'selection', 'authentication', 'request', 'output', 'retirement'] as const) {
    const error = new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, stage);
    assert.equal(error.diagnostic.lastObservedDriverStage, stage); assert(Object.isFrozen(error.diagnostic));
  }
});

test('authentication data never invokes supplied accessors or serializes unknown objects', () => {
  let accessed = false;
  const poison = Object.defineProperty({}, 'package', { get() { accessed = true; throw 0; } });
  assert.throws(() => copyInstalledClientAuthenticationWork(poison), assert.AssertionError);
  assert.throws(() => installedClientAuthenticationMarker('hello_sent' as never, 0));
  const rows = Array(1);
  Object.defineProperty(rows, '0', { get() { accessed = true; throw 0; } });
  assert.throws(() => new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, undefined, rows), assert.AssertionError);
  assert.equal(accessed, false);
});

test('driver failure copies only a closed immutable authentication prefix and refuses malformed data without traps', () => {
  const row = { stage: 'manager_observer_loaded' as const, elapsedMs: 1, observedElapsedMs: 2 };
  const input = [row], failure = new InstalledClientDriverError('authentication', input);
  row.elapsedMs = 10;
  assert.equal(failure.diagnostic.authentication?.[0]?.elapsedMs, 1);
  assert(Object.isFrozen(failure.diagnostic) && Object.isFrozen(failure.diagnostic.authentication) && Object.isFrozen(failure.diagnostic.authentication?.[0]));
  let traps = 0;
  const getter = Object.defineProperty({}, 'stage', { enumerable: true, get() { traps++; throw 0; } });
  const arrayGetter = Object.defineProperty([row], '0', { enumerable: true, get() { traps++; throw 0; } });
  const proxy = new Proxy(row, { ownKeys() { traps++; throw 0; }, get() { traps++; throw 0; } });
  const arrayProxy = new Proxy(input, { ownKeys() { traps++; throw 0; }, get() { traps++; throw 0; } });
  const extra = [row]; Object.defineProperty(extra, 'extra', { value: 'not retained' });
  const hidden = Object.defineProperty([row], '0', { value: row, enumerable: false });
  for (const data of [null, [getter], arrayGetter, arrayProxy, [proxy], extra, hidden, Array(1), [row, row],
    [{ ...row, extra: true }], [{ ...row, stage: 'private stage' }], [{ ...row, elapsedMs: -1 }],
    [{ ...row, observedElapsedMs: Number.MAX_SAFE_INTEGER + 1 }]])
    assert.throws(() => new InstalledClientDriverError('authentication', data as never), assert.AssertionError);
  assert.equal(traps, 0);
  assert.deepEqual(new InstalledClientDriverError('authentication', []).diagnostic, { kind: 'installed_client_driver', stage: 'authentication' });
});

test('V2 labels only explicitly supplied self whole-process cumulative counters and keeps V1 bytes unchanged', () => {
  const process = { userCPUTime: 100, systemCPUTime: 20, fsRead: 3, fsWrite: 4 };
  assert.equal(installedClientAuthenticationMarker('native_connected', 12, undefined, process).toString('ascii'),
    'CLIQ_INSTALLED_CLIENT_AUTH_V2:self_whole_process_cumulative:native_connected:12:none:100:20:3:4\n');
  assert.equal(installedClientAuthenticationMarker('native_connected', 12).toString('ascii'),
    'CLIQ_INSTALLED_CLIENT_AUTH_V1:native_connected:12:none\n');
});

test('self process snapshots are exactly four primitive counters without getters or borrowed objects', () => {
  const sample = { userCPUTime: 100, systemCPUTime: 20, fsRead: 3, fsWrite: 4 };
  const result = copyInstalledClientAuthenticationProcess(sample); sample.userCPUTime = 101;
  assert.deepEqual(result, { userCPUTime: 100, systemCPUTime: 20, fsRead: 3, fsWrite: 4 }); assert(Object.isFrozen(result));
  let accessed = 0;
  const getter = { ...sample }; Object.defineProperty(getter, 'userCPUTime', { enumerable: true, get() { accessed++; throw 0; } });
  const hidden = { ...sample }; Object.defineProperty(hidden, 'fsRead', { value: 3, enumerable: false });
  const symbol = { ...sample, [Symbol('extra')]: 0 };
  const proxy = new Proxy(sample, { ownKeys() { accessed++; throw 0; }, get() { accessed++; throw 0; } });
  for (const value of [getter, hidden, symbol, proxy, { ...sample, bytesRead: 0 }, [100, 20, 3, 4], null]) {
    assert.throws(() => copyInstalledClientAuthenticationProcess(value));
  }
  for (const key of ['userCPUTime', 'systemCPUTime', 'fsRead', 'fsWrite']) {
    for (const value of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '3', {}, undefined]) {
      assert.throws(() => copyInstalledClientAuthenticationProcess({ ...sample, [key]: value }));
    }
  }
  assert.equal(accessed, 0);
});

test('self process cumulative counters never reset across an intervening V1 phase', () => {
  const own = { userCPUTime: 100, systemCPUTime: 20, fsRead: 3, fsWrite: 4 };
  const rows = [
    { stage: 'manager_observer_loaded', elapsedMs: 1, observedElapsedMs: 1, process: own },
    { stage: 'initial_current_observed', elapsedMs: 2, observedElapsedMs: 2 },
    { stage: 'native_connected', elapsedMs: 3, observedElapsedMs: 3, process: { ...own } },
  ] as const;
  const error = new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, 'authentication', rows);
  assert.deepEqual(error.diagnostic.authentication?.map(row => row.process), [own, undefined, own]);
  assert(Object.isFrozen(error.diagnostic.authentication?.[0]?.process));
  for (const key of ['userCPUTime', 'systemCPUTime', 'fsRead', 'fsWrite'] as const) {
    const lower = rows.map(row => ({ ...row })); lower[2] = { ...rows[2], process: { ...own, [key]: own[key] - 1 } };
    assert.throws(() => new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, 'authentication', lower));
  }
  const max = Number.MAX_SAFE_INTEGER;
  const work = { package: { started: max, completed: max, bytesRead: max, spanElapsedMs: max },
    revalidate: { started: max, completed: max, bytesRead: max, spanElapsedMs: max },
    createCompare: { started: max, completed: max, bytesRead: 0, spanElapsedMs: max } };
  assert(installedClientAuthenticationMarker('final_current_verified', max, work,
    { userCPUTime: max, systemCPUTime: max, fsRead: max, fsWrite: max }).length <= 512);
});

test('split V2 prefixes and counters are scanned before retention under the original ready deadline and actual join', async () => {
  const marker = 'CLIQ_INSTALLED_CLIENT_AUTH_V2:self_whole_process_cumulative:hello_exchange_started:12:1:1:10:3:2:2:20:4:0:0:0:0:100:20:3:4\n';
  const pieces = [marker.slice(0, 22), marker.slice(22, 48), marker.slice(48, -3), marker.slice(-3)];
  const scanned: Buffer[] = []; let closed = 0;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `for(const piece of ${JSON.stringify(pieces)}){
      process.stderr.write(piece);await new Promise(r=>setTimeout(r,10));}for await(const _ of process.stdin){}`],
    cwd: process.cwd(), env: process.env, timeout: 500,
    openScan: () => ({ scan(bytes) { scanned.push(Buffer.from(bytes)); }, close() { closed++; } }), onJoined() { assert.fail(); }
  }), error => {
    assert(error instanceof InstalledClientConsumerDeadlineError); assert.equal(error.diagnostic.originalDeadlineMs, 500);
    assert.equal(error.diagnostic.frames, 0); const rows = error.diagnostic.authentication; assert.equal(rows?.length, 1);
    assert.deepEqual(rows[0]?.process, { userCPUTime: 100, systemCPUTime: 20, fsRead: 3, fsWrite: 4 });
    assert.equal(rows[0]?.work?.revalidate.bytesRead, 20); assert(Object.isFrozen(rows[0]?.process)); return true;
  });
  assert.equal(Buffer.concat(scanned).toString(), marker); assert.equal(closed, 2);
});

test('all seven V2 phases remain bounded scanned diagnostics and permit the unchanged real JSONL pipe join', async () => {
  const stages = ['manager_observer_loaded', 'initial_current_observed', 'native_connected', 'pre_hello_current_verified',
    'hello_exchange_started', 'hello_received', 'final_current_verified'] as const;
  const markers = stages.map((stage, i) => installedClientAuthenticationMarker(stage, i, undefined,
    { userCPUTime: i, systemCPUTime: i, fsRead: i, fsWrite: i }).toString()).join('');
  const scanned: Buffer[] = []; let closed = 0, joined = 0;
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `process.stderr.write(${JSON.stringify(markers)});${protocol}`],
    cwd: process.cwd(), env: process.env,
    openScan: () => ({ scan(bytes) { scanned.push(Buffer.from(bytes)); }, close() { closed++; } }), onJoined() { joined++; } });
  assert.equal((await client.send({ protocolVersion: 1, method: 'run.get' })).result?.count, 1);
  await client.close(); assert.equal(joined, 1); assert.equal(closed, 2);
  assert(Buffer.concat(scanned).includes(Buffer.from(markers)));
});

test('malformed V2 labels, counter encodings and decreasing counters stay fatal without V1 borrowing', async () => {
  const prefix = 'CLIQ_INSTALLED_CLIENT_AUTH_V2:self_whole_process_cumulative:';
  const valid = prefix + 'native_connected:4:none:100:20:3:4\n';
  const gap = 'CLIQ_INSTALLED_CLIENT_AUTH_V1:hello_exchange_started:5:none\n';
  const bad = [prefix.replace('self_whole_process', 'single_thread') + 'native_connected:4:none:1:2:3:4\n',
    prefix + 'native_connected:4:none:1:2:3\n', prefix + 'native_connected:4:none:1:2:3:4:5\n',
    'CLIQ_INSTALLED_CLIENT_AUTH_V1:native_connected:4:none:1:2:3:4\n', valid.trimEnd(),
    prefix + 'native_connected:4:none:1:2:3:4\u00ff\n'];
  for (const encoded of ['-1', '01', '1e3', '0.5', '9007199254740992']) bad.push(prefix + `native_connected:4:none:${encoded}:2:3:4\n`);
  for (const counters of ['99:20:3:4', '100:19:3:4', '100:20:2:4', '100:20:3:3']) {
    bad.push(valid + gap + prefix + `hello_received:6:none:${counters}\n`);
  }
  for (const marker of bad) {
    const bytes = Buffer.from(marker), scanned: Buffer[] = []; let opened = 0, closed = 0, joined = false, refused = false;
    try {
      const client = await openInstalledClientConsumer({ executable: process.execPath,
        args: ['--input-type=module', '-e', `process.stderr.write(Buffer.from('${bytes.toString('base64')}','base64'));
          process.stdout.write('{"ok":true,"protocolVersion":1,"result":{"method":"control.hello","supervisorInstanceId":"owned-framing-fixture"}}\\n');
          for await(const _ of process.stdin){}`], cwd: process.cwd(), env: process.env,
        openScan: () => { const stderr = ++opened === 2; return { scan(chunk) { if (stderr) scanned.push(Buffer.from(chunk)); }, close() { closed++; } }; },
        onJoined() { joined = true; } });
      await client.close();
    } catch (error) { assert(!(error instanceof InstalledClientConsumerDeadlineError)); refused = true; }
    assert(refused); assert.equal(joined, false); assert.equal(closed, 2); assert(Buffer.concat(scanned).equals(bytes));
  }
});

test('the original secret scanner can refuse V2 before any process observation is retained', async () => {
  const blocked = new Error('owned V2 scanner refusal'); let opened = 0, closed = 0;
  const marker = 'CLIQ_INSTALLED_CLIENT_AUTH_V2:self_whole_process_cumulative:native_connected:0:none:1:2:3:4\n';
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `process.stderr.write(${JSON.stringify(marker)});for await(const _ of process.stdin){}`],
    cwd: process.cwd(), env: process.env,
    openScan: () => { const stderr = ++opened === 2; return { scan() { if (stderr) throw blocked; }, close() { closed++; } }; },
    onJoined() { assert.fail(); } }), error => error === blocked);
  assert.equal(closed, 2);
});

test('unknown, partial, duplicate, unordered or invalid authentication markers remain fatal scanned stderr', async () => {
  const prefix = 'CLIQ_INSTALLED_CLIENT_AUTH_V1:';
  const valid = prefix + 'native_connected:4:none\n';
  const bad = [prefix + 'hello_sent:1:none\n', valid + valid,
    valid + prefix + 'initial_current_observed:5:none\n',
    valid + prefix + 'hello_received:3:none\n', prefix + 'native_connected:9007199254740992:none\n',
    prefix + 'native_connected:4:1:2:0:0:0:0:0:0:0:0:0:0\n',
    prefix + 'native_connected:4:0:0:0:0:0:0:0:0:1:1:1:0\n',
    prefix + 'native_connected:4:1:1:10:1:1:1:20:1:0:0:0:0\n' +
      prefix + 'hello_received:5:1:1:9:1:1:1:20:1:0:0:0:0\n',
    prefix + 'native_connected:4:none', prefix + 'native_connected:' + '1'.repeat(513),
    prefix + 'native_connected:4:none:extra\n', prefix + 'native_connected:4:n\u00ffne\n'];
  for (const value of bad) {
    const bytes = Buffer.from(value), scanned: Buffer[] = []; let opened = 0, closed = 0;
    let refused = false;
    try {
      const client = await openInstalledClientConsumer({ executable: process.execPath,
        args: ['--input-type=module', '-e', `process.stderr.write(Buffer.from('${bytes.toString('base64')}','base64'));
          process.stdout.write('{"ok":true,"protocolVersion":1,"result":{"method":"control.hello","supervisorInstanceId":"owned-framing-fixture"}}\\n');
          for await(const _ of process.stdin){}`], cwd: process.cwd(), env: process.env,
        openScan: () => { const stderr = ++opened === 2; return { scan(chunk) { if (stderr) scanned.push(Buffer.from(chunk)); }, close() { closed++; } }; }, onJoined() {}
      });
      await client.close();
    } catch (error) { assert(!(error instanceof InstalledClientConsumerDeadlineError)); refused = true; }
    assert(refused, 'invalid authentication data cannot become a successful ready/close');
    assert(Buffer.concat(scanned).equals(bytes)); assert.equal(closed, 2);
  }
});

test('the secret scanner can refuse authentication data before any diagnostic is retained', async () => {
  const blocked = new Error('owned authentication scan refusal'); let opened = 0, closed = 0;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', "process.stderr.write('CLIQ_INSTALLED_CLIENT_AUTH_V1:native_connected:0:none\\n');for await(const _ of process.stdin){}"],
    cwd: process.cwd(), env: process.env,
    openScan: () => { const stderr = ++opened === 2; return { scan() { if (stderr) throw blocked; }, close() { closed++; } }; },
    onJoined() { assert.fail(); }
  }), error => error === blocked);
  assert.equal(closed, 2);
});

test('unknown, duplicate and incomplete stderr never become accepted driver progress or a positive join', async () => {
  for (const bytes of [
    Buffer.from('private remote diagnostic\ninstalled control client driver progress phase=selection\n'),
    Buffer.from('installed control client driver progress phase=unknown\n'),
    Buffer.from('installed control client driver progress phase=selection'),
    Buffer.from('installed control client driver progress phase=selection\ninstalled control client driver progress phase=selection\n'),
    Buffer.concat([Buffer.from('installed control client driver progress phase=select'), Buffer.from([0xff]), Buffer.from('ion\n')])
  ]) {
    const scanned: Buffer[] = []; let closed = 0, joined = false;
    await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
      args: ['--input-type=module', '-e', `process.stderr.write(Buffer.from('${bytes.toString('base64')}', 'base64'));`],
      cwd: process.cwd(), env: process.env,
      openScan: () => ({ scan(chunk) { scanned.push(Buffer.from(chunk)); }, close() { closed++; } }),
      onJoined() { joined = true; }
    }), error => {
      assert(!(error instanceof InstalledClientConsumerDeadlineError));
      assert(!String(error).includes('private remote diagnostic')); return true;
    });
    assert(Buffer.concat(scanned).equals(bytes)); assert.equal(closed, 2); assert.equal(joined, false);
  }
});

test('a fixed failure marker remains fatal after progress and hello without resending the mutation', async () => {
  let closed = 0, joined = false;
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `import {createInterface} from 'node:readline';
      process.stderr.write('installed control client driver progress phase=authentication\\n');
      process.stdout.write('{"ok":true,"protocolVersion":1,"result":{"method":"control.hello","supervisorInstanceId":"owned-framing-fixture"}}\\n');
      let count=0;for await(const _ of createInterface({input:process.stdin,crlfDelay:Infinity})) {
        if(++count!==1)process.exitCode=2;
        process.stderr.write('installed control client driver failed phase=request\\n');
      }`], cwd: process.cwd(), env: process.env,
    openScan: () => ({ scan() {}, close() { closed++; } }), onJoined() { joined = true; }
  });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }), error => {
    assert(error instanceof InstalledClientDriverError);
    assert.deepEqual(error.diagnostic, { kind: 'installed_client_driver', stage: 'request' }); return true;
  });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await assert.rejects(client.close()); assert.equal(closed, 2); assert.equal(joined, false);
});

test('the original secret scanner may refuse a fixed progress marker before it enters diagnostics', async () => {
  const blocked = new Error('owned scanner refusal'); let opened = 0, closed = 0;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', "process.stderr.write('installed control client driver progress phase=authentication\\n');for await(const _ of process.stdin){}"],
    cwd: process.cwd(), env: process.env,
    openScan: () => { const stderr = ++opened === 2; return {
      scan(bytes) { if (stderr) { assert(Buffer.from(bytes).includes(Buffer.from('progress phase='))); throw blocked; } },
      close() { closed++; }
    }; }, onJoined() { assert.fail('a scanner refusal cannot become a joined consumer'); }
  }), error => error === blocked);
  assert.equal(opened, 2); assert.equal(closed, 2);
});
