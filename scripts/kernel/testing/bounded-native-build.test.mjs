import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createWorkerBuildScope } from '../build-bubblewrap.mjs';

// Real ordinary Node subprocesses model non-daemonizing compiler/launcher
// scheduling only. Their data output is never an image/signature/installation
// or native resource/death authority. No C, Meson, network or namespace runs.
const posix = process.platform !== 'win32';
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function temporary(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-build-process-data-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}
async function waitFile(filename) {
  const deadline = Date.now() + 5000;
  for (;;) {
    try { return await readFile(filename, 'utf8'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (Date.now() >= deadline) throw new Error('Controlled build child did not become ready');
    await pause(10);
  }
}
function own(t, signal) {
  const scope = createWorkerBuildScope(signal);
  t.after(async () => {
    scope.abort(new Error('Controlled build test is complete'));
    try { await scope.join(); } finally { scope.dispose(); }
  });
  return scope;
}
const command = code => ['-e', code];
function absent(pid) {
  assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH');
}
function idleChild(marker) {
  return `require('node:fs').writeFileSync(${JSON.stringify(marker)},String(process.pid));
    process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);`;
}
function work(label, barrier = '') {
  return `const emit=kind=>console.log(JSON.stringify({kind,label:${JSON.stringify(label)},at:String(process.hrtime.bigint())}));
    emit('start'); ${barrier} const until=performance.now()+70; while(performance.now()<until){} emit('end');`;
}

test('all command families share exactly two lanes through real child close', { skip: !posix, timeout: 10000 }, async t => {
  const directory = await temporary(t), scope = own(t);
  const barrier = (name, peer) => `const fs=require('node:fs');fs.writeFileSync(${JSON.stringify(path.join(directory, name))},'ready');
    while(!fs.existsSync(${JSON.stringify(path.join(directory, peer))}))Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5);`;
  const nested = `const {spawnSync}=require('node:child_process');
    for(const code of ${JSON.stringify([work('meson-like-1', barrier('nested', 'plain')), work('meson-like-2')])}) {
      const child=spawnSync(process.execPath,['-e',code],{encoding:'utf8'});
      process.stdout.write(child.stdout); if(child.status!==0)process.exit(1);
    }`;
  const results = await Promise.all([
    scope.run(process.execPath, command(nested)),
    scope.run(process.execPath, command(work('controller-like', barrier('plain', 'nested')))),
    ...['addon-like', 'worker-like', 'extractor-like'].map(label => scope.run(process.execPath, command(work(label)))),
  ]);
  await scope.join();
  assert(scope.retired());
  const events = results.flatMap(result => result.stdout.trim().split('\n').map(line => JSON.parse(line)))
    .sort((a, b) => BigInt(a.at) < BigInt(b.at) ? -1 : 1);
  let running = 0, peak = 0;
  for (const event of events) {
    running += event.kind === 'start' ? 1 : -1;
    assert(running >= 0 && running <= 2);
    peak = Math.max(peak, running);
  }
  assert.equal(peak, 2); assert.equal(running, 0); assert.equal(events.length, 12);
});

test('a failed command revokes queued work and joins its already running peer', { skip: !posix, timeout: 10000 }, async t => {
  const directory = await temporary(t), ready = path.join(directory, 'peer'), forbidden = path.join(directory, 'queued');
  const scope = own(t);
  const peer = scope.run(process.execPath, command(idleChild(ready)));
  const peerPid = Number(await waitFile(ready));
  const failed = scope.run(process.execPath, command("process.stderr.write('controlled failure');process.exit(7)"));
  const queued = scope.run(process.execPath, command(`require('node:fs').writeFileSync(${JSON.stringify(forbidden)},'started')`));
  const results = await Promise.allSettled([peer, failed, queued]);
  assert(results.every(result => result.status === 'rejected'));
  assert.equal(results[1].reason.code, 7); assert.equal(results[1].reason.stderr, 'controlled failure');
  await scope.join(); absent(peerPid);
  await assert.rejects(access(forbidden), error => error.code === 'ENOENT');
});

test('cancellation kills a launcher group after the launcher exited while descendants hold pipes', { skip: !posix, timeout: 10000 }, async t => {
  const directory = await temporary(t), ready = path.join(directory, 'grandchild');
  const controller = new AbortController(), scope = own(t, controller.signal);
  const launcher = `require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(idleChild(ready))}],{stdio:'inherit'});
    process.exit(0);`;
  const result = scope.run(process.execPath, command(launcher));
  const childPid = Number(await waitFile(ready));
  controller.abort(new Error('Controlled build cancellation'));
  await assert.rejects(result, /Controlled build cancellation/u);
  await scope.join(); absent(childPid); assert(scope.retired());
});

test('zero-exit launcher with a closed-pipe surviving descendant cannot succeed', { skip: !posix, timeout: 10000 }, async t => {
  const directory = await temporary(t), ready = path.join(directory, 'closed-pipe-child');
  const scope = own(t);
  const launcher = `const fs=require('node:fs');
    require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(idleChild(ready))}],{stdio:'ignore'});
    const wait=setInterval(()=>{if(fs.existsSync(${JSON.stringify(ready)})){clearInterval(wait);process.exit(0)}},5);`;
  const result = scope.run(process.execPath, command(launcher));
  const rejected = assert.rejects(result, /unjoined process group/u);
  const childPid = Number(await waitFile(ready));
  await rejected;
  await scope.join(); absent(childPid);
});

test('spawn failure cancels peers and preserves the actual spawn error', { skip: !posix, timeout: 10000 }, async t => {
  const directory = await temporary(t), ready = path.join(directory, 'spawn-peer');
  const scope = own(t), peer = scope.run(process.execPath, command(idleChild(ready)));
  const peerPid = Number(await waitFile(ready));
  const missing = scope.run(path.join(directory, 'absent-compiler'), []);
  const results = await Promise.allSettled([peer, missing]);
  assert.equal(results[1].status, 'rejected'); assert.equal(results[1].reason.code, 'ENOENT');
  await scope.join(); absent(peerPid);
});

test('the original capture bound cancels and joins before returning an overflow', { skip: !posix, timeout: 10000 }, async t => {
  const scope = own(t);
  const result = scope.run(process.execPath, command("process.stdout.write(Buffer.alloc(1024*1024+1,120));setInterval(()=>{},1000)"));
  await assert.rejects(result, /original 1MiB bound/u);
  await scope.join(); assert(scope.retired());
});

test('command timeout and pre-aborted admission never start a replacement command', { skip: !posix, timeout: 10000 }, async t => {
  const scope = own(t);
  const first = scope.run(process.execPath, command('setInterval(()=>{},1000)'), { timeout: 50 });
  await assert.rejects(first, /timed out/u);
  await scope.join();
  await assert.rejects(scope.run(process.execPath, command("throw Error('must not start')")), /timed out/u);
  const controller = new AbortController(); controller.abort(new Error('Already cancelled'));
  const cancelled = own(t, controller.signal);
  await assert.rejects(cancelled.run(process.execPath, command("throw Error('must not start')")), /Already cancelled/u);
  await cancelled.join();
  const falseReason = new AbortController(); falseReason.abort(false);
  const alsoCancelled = own(t, falseReason.signal);
  await assert.rejects(alsoCancelled.run(process.execPath, command("throw Error('must not start')")), reason => reason === false);
  await alsoCancelled.join();
  const nullReason = new AbortController(); nullReason.abort(null);
  const nullCancelled = own(t, nullReason.signal);
  await assert.rejects(nullCancelled.run(process.execPath, command("throw Error('must not start')")), reason => reason === null);
  await nullCancelled.join();
});

test('outer SIGTERM revokes detached build children and joins before the owner returns', { skip: !posix, timeout: 10000 }, async t => {
  const directory = await temporary(t), ready = path.join(directory, 'signal-child');
  const moduleUrl = new URL('../build-bubblewrap.mjs', import.meta.url).href;
  const code = `import {createWorkerBuildScope} from ${JSON.stringify(moduleUrl)};
    const scope=createWorkerBuildScope();
    try {await scope.run(process.execPath,['-e',${JSON.stringify(idleChild(ready))}]);throw Error('unexpected success')}
    catch(error){if(!/received SIGTERM/.test(error.message))throw error}
    finally {try{await scope.join()}finally{scope.dispose()}}
    console.log('CONTROLLED_BUILD_JOINED');`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', closed = false;
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', part => { stdout += part; }); child.stderr.on('data', part => { stderr += part; });
  const joined = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (status, signal) => { closed = true; resolve({ status, signal }); });
  });
  let ownedPid;
  t.after(async () => {
    if (!closed) {
      child.kill('SIGTERM');
      if (ownedPid) { try { process.kill(-ownedPid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
      await joined;
    }
  });
  ownedPid = Number(await waitFile(ready));
  child.kill('SIGTERM');
  const result = await joined;
  assert.deepEqual(result, { status: 0, signal: null }, stderr);
  assert.equal(stdout, 'CONTROLLED_BUILD_JOINED\n'); absent(ownedPid);
});
