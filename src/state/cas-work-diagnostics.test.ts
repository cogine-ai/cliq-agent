// Real owned CAS files and inert counters, not Run/native authority or timing qualification.
import assert from 'node:assert/strict';
import { channel } from 'node:diagnostics_channel';
import { spawnSync } from 'node:child_process';
import { fstatSync, promises as fs, readdirSync } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { ContentAddressedStore, ARTIFACT_CHUNK_BYTES } from './cas.js';
import { beginInstalledSubmitDiagnostic, noteInstalledStoreStop } from './installed-run-diagnostics.js';
import { observeInstalledWork, noteInstalledWorkRead } from './installed-work-diagnostics.js';
import type { InstalledAssemblyWorkSnapshot } from './installed-work-diagnostics.js';
import { ResourceRetirementError } from './errors.js';

test('first-submit cuts retain complete real CAS lifetimes and exact returned bytes without changing the old work payload', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-work-'));
  const diagnostic = channel('cliq.installed.assembly.work.v1'), packets: InstalledAssemblyWorkSnapshot[] = [];
  const subscriber = (value: unknown) => packets.push(value as InstalledAssemblyWorkSnapshot);
  diagnostic.subscribe(subscriber);
  try {
    const root = path.join(home, 'objects'); await mkdir(root, { mode: 0o700 });
    const cas = new ContentAddressedStore(root), bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES + 7, 0x41);
    const request = beginInstalledSubmitDiagnostic();
    assert.equal(packets.length, 1, 'the trusted server subscriber must observe the actual first submit boundary');
    const ref = await cas.publish(bytes);
    assert.deepEqual(await cas.read(ref), bytes);
    assert.deepEqual(await cas.verify(ref), { ref, byteLength: bytes.length });
    const unopened = cas.readChunks(ref, bytes.length); await unopened.return(undefined);
    const chunks = cas.readChunks(ref, bytes.length);
    assert.equal((await chunks.next()).value!.length, ARTIFACT_CHUNK_BYTES);
    request!.stage('submit_assembly_material');
    const active = packets.at(-1)!.casRead;
    assert.equal(active.started, 3); assert.equal(active.settled, 2);
    await chunks.return(undefined);
    await observeInstalledWork('revalidate', async () => { noteInstalledWorkRead(19); });
    await cas.publishFour([Buffer.from('one'), Buffer.from('two'), Buffer.from('three'), Buffer.from('four')]);
    request!.stage('submit_assembly_verifier_history');
    const packet = packets.at(-1)!;
    assert.equal(packet.casRead.started, 3); assert.equal(packet.casRead.settled, 3);
    assert.equal(packet.casRead.bytesRead, 2 * bytes.length + ARTIFACT_CHUNK_BYTES);
    assert.equal(packet.publishFour.started, 1); assert.equal(packet.publishFour.settled, 1);
    assert.equal(packet.fileSync.started, 5); assert.equal(packet.fileSync.settled, 5);
    assert.equal(packet.rootSync.started, 8); assert.equal(packet.rootSync.settled, 8);
    assert.equal(packet.runtime.revalidate.bytesRead, 19);
    assert.equal(packet.runtime.revalidate.completed, 1);
    assert.deepEqual(Object.keys(packet.runtime), ['package', 'revalidate', 'createCompare']);
    assert(Object.isFrozen(packet) && Object.isFrozen(packet.casRead));
    assert(!JSON.stringify(packets).includes(home));
    // This is the actual held root's close, not a fake read or native owner.
    // The complete ordinary read must remain active until this real join ends.
    const actualOpen = fs.open;
    let entered!: () => void, release!: () => void;
    const closing = new Promise<void>(resolve => { entered = resolve; });
    const proceed = new Promise<void>(resolve => { release = resolve; });
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await actualOpen(...args);
      if (args[0] === root) {
        const close = handle.close.bind(handle);
        handle.close = async () => { entered(); await proceed; await close(); };
      }
      return handle;
    }) as typeof fs.open;
    const pending = cas.read(ref);
    let returned = false, readError: unknown;
    const joined = pending.then(() => { returned = true; }, error => { readError = error; });
    try {
      await Promise.race([closing, joined.then(() => { throw new Error('original read ended before its owned close gate'); })]);
      request!.stage('submit_assembly_verifier_current');
      assert.equal(returned, false); assert.equal(packets.at(-1)!.casRead.started, 4);
      assert.equal(packets.at(-1)!.casRead.settled, 3, 'a held root awaiting close is not a settled read');
    } finally { release(); await Promise.allSettled([pending, joined]); fs.open = actualOpen; }
    await joined; assert.equal(readError, undefined); request!.stage('submit_assembly_verifier_compose');
    assert.equal(packets.at(-1)!.casRead.settled, 4);
    noteInstalledStoreStop({ driverTasks: 0, agentLoads: 0, admissions: 0, retainedFailures: 0, globalFailure: false, phases: [] });
    assert.equal(packets.at(-1)!.phase, 'original_store_stop');
    const count = packets.length;
    request!.stage('submit_assembly_verifier_current'); beginInstalledSubmitDiagnostic();
    assert.equal(packets.length, count, 'another request cannot be attributed to the first window');
  } finally { diagnostic.unsubscribe(subscriber); await rm(home, { recursive: true, force: true }); }
});

function assertJoined(identities: Array<{ dev: number; ino: number }>): void {
  for (const entry of readdirSync(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd')) {
    if (!/^\d+$/u.test(entry)) continue;
    let info; try { info = fstatSync(Number(entry)); } catch { continue; }
    assert(!identities.some(value => value.dev === info.dev && value.ino === info.ino), 'every original real descriptor must join');
  }
}

for (const mode of ['read', 'verify', 'chunks'] as const) for (const closeFails of [false, true])
  test(`subscribed ${mode} preserves actual returned-read cancellation, joined descriptors and close priority (${closeFails})`, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-work-abort-'));
    const cas = new ContentAddressedStore(root), bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES + 5, 0x63), ref = await cas.publish(bytes);
    const diagnostic = channel('cliq.installed.assembly.work.v1'), subscriber = () => {};
    const original = new Error('original cancellation'), closeFailure = new Error('original uncertain close');
    const owner = new AbortController(), actualOpen = fs.open, identities: Array<{dev:number;ino:number}> = [];
    let reads = 0;
    diagnostic.subscribe(subscriber);
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await actualOpen(...args); identities.push(await handle.stat());
      if (args[0] === path.join(root, ref)) {
        const read = handle.read.bind(handle), close = handle.close.bind(handle);
        handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
          const result = await read(...readArgs); reads++; owner.abort(original); return result;
        }) as typeof handle.read;
        if (closeFails) handle.close = async () => { await close(); throw closeFailure; };
      }
      return handle;
    }) as typeof fs.open;
    try {
      await assert.rejects(async () => {
        if (mode === 'read') await cas.read(ref, owner.signal);
        else if (mode === 'verify') await cas.verify(ref, owner.signal);
        else for await (const _part of cas.readChunks(ref, bytes.length, owner.signal)) { /* Full original reader. */ }
      }, error => closeFails ? error instanceof ResourceRetirementError && error.cause === closeFailure : error === original);
      assert.equal(reads, 1); assertJoined(identities);
    } finally { fs.open = actualOpen; diagnostic.unsubscribe(subscriber); await rm(root, { recursive: true, force: true }); }
  });

for (const kind of ['file', 'root'] as const) test(`subscribed fixed-four ${kind} sync rejection preserves the original error and cleanup join`, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-work-sync-'));
  const diagnostic = channel('cliq.installed.assembly.work.v1'), subscriber = () => {};
  const actualOpen = fs.open, original = new Error('original actual sync rejection'), identities: Array<{dev:number;ino:number}> = [];
  let failed = false;
  diagnostic.subscribe(subscriber);
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if ((args[0] === root) === (kind === 'root')) {
      const sync = handle.sync.bind(handle);
      handle.sync = async () => { await sync(); if (!failed) { failed = true; throw original; } };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(new ContentAddressedStore(root).publishFour([Buffer.from('a'), Buffer.from('b'), Buffer.from('c'), Buffer.from('d')]),
      error => kind === 'root' ? error instanceof ResourceRetirementError && error.cause === original : error === original);
    assert.equal(failed, true); assertJoined(identities);
    assert((await fs.readdir(root)).every(name => /^[a-f0-9]{64}$/u.test(name)), 'all original temporary cleanup must complete');
  } finally { fs.open = actualOpen; diagnostic.unsubscribe(subscriber); await rm(root, { recursive: true, force: true }); }
});

test('unsubscribed real CAS operations sample no diagnostic clock and retain the original work call', () => {
  const casUrl = new URL('./cas.ts', import.meta.url).href, workUrl = new URL('./installed-work-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=module', '--eval', `
    import {mkdtemp,rm} from 'node:fs/promises'; import os from 'node:os'; import path from 'node:path';
    const {ContentAddressedStore}=await import(${JSON.stringify(casUrl)});
    const {observeInstalledWork,noteInstalledWorkRead}=await import(${JSON.stringify(workUrl)});
    const root=await mkdtemp(path.join(os.tmpdir(),'cliq-no-work-'));let calls=0;
    Object.defineProperty(performance,'now',{value:()=>{throw Error('unexpected diagnostic clock')}});
    try {const cas=new ContentAddressedStore(root),ref=await cas.publish(Buffer.from('abc'));
      await cas.read(ref);await cas.verify(ref);for await(const chunk of cas.readChunks(ref,3)){}
      await cas.publishFour([Buffer.from('a'),Buffer.from('b'),Buffer.from('c'),Buffer.from('d')]);
      const result=await observeInstalledWork('package',async()=>{calls++;noteInstalledWorkRead(3);return 17});
      if(calls!==1||result!==17)throw Error('original operation changed');
    }finally{await rm(root,{recursive:true,force:true})}
  `], { encoding: 'utf8', timeout: 5000, cwd: new URL('../..', import.meta.url) });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});

test('a failed trusted measurement clock cannot replace the actual runtime operation or its original error', () => {
  const workUrl = new URL('./installed-work-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=module', '--eval', `
    import {channel} from 'node:diagnostics_channel';
    const {observeInstalledWork}=await import(${JSON.stringify(workUrl)});
    channel('cliq.installed.assembly.work.v1').subscribe(()=>{});
    Object.defineProperty(performance,'now',{value:()=>{throw Error('unavailable diagnostic clock')}});
    let calls=0;const original=Error('original work rejection');
    try {await observeInstalledWork('revalidate',async()=>{calls++;throw original});throw Error('original work accepted')}
    catch(error){if(error!==original)throw Error('measurement replaced original operation')}
    if(calls!==1)throw Error('original operation was not invoked exactly once');
  `], { encoding: 'utf8', timeout: 5000, cwd: new URL('../..', import.meta.url) });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});

test('the old WORK stream also becomes explicitly truncated when its original span clock is unavailable', () => {
  const workUrl = new URL('./installed-work-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=module', '--eval', `
    import assert from 'node:assert/strict';import {channel} from 'node:diagnostics_channel';
    const {observeInstalledWork}=await import(${JSON.stringify(workUrl)});
    const rows=[],assembly=[];channel('cliq.installed.work.v1').subscribe(value=>rows.push(value));
    channel('cliq.installed.assembly.work.v1').subscribe(value=>assembly.push(value));
    const now=performance.now.bind(performance);let calls=0;
    Object.defineProperty(performance,'now',{configurable:true,value:()=>{calls++;if(calls===3)throw Error('unavailable span finish clock');return now()}});
    const original=Error('actual operation rejection');
    await assert.rejects(observeInstalledWork('revalidate',async()=>{throw original}),error=>error===original);
    Object.defineProperty(performance,'now',{configurable:true,value:now});
    await observeInstalledWork('revalidate',async()=>17);
    const index=rows.indexOf('truncated');assert(index>=0,'old WORK must explicitly reject incomplete measurement');
    assert(rows.slice(index).every(value=>value==='truncated'),'old WORK must never publish partial elapsed as normal');
    assert(assembly.includes('truncated'),'the new stream must also remain unavailable');
  `], { encoding: 'utf8', timeout: 5000, cwd: new URL('../..', import.meta.url) });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
