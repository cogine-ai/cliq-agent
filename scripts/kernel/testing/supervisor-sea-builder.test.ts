import assert from 'node:assert/strict';
import './supervisor-sea-application.test.js';
import { spawnSync } from 'node:child_process';
import { access, chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { CREDENTIAL_PHASE_DIAGNOSTIC_BANNER, INSTALLED_WORK_DIAGNOSTIC_BANNER,
  copyWritableSupervisorSeaImage, prepareSupervisorSeaCarrier, SUPERVISOR_SEA_NODE_VERSION } from './supervisor-sea-builder.js';

test('a read-only carrier creates a fresh owner-writable SEA output without changing its source', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-sea-writable-copy-'));
  try {
    const source = path.join(fixture, 'carrier'), output = path.join(fixture, 'supervisor');
    const bytes = Buffer.from('complete original image fixture\n');
    await writeFile(source, bytes, { flag: 'wx', mode: 0o500 });
    const before = await lstat(source, { bigint: true });
    await copyWritableSupervisorSeaImage(source, output);
    const copied = await lstat(output, { bigint: true });
    assert(copied.isFile()); assert.equal(copied.nlink, 1n);
    assert.equal(copied.uid, BigInt(process.geteuid!())); assert.equal(copied.gid, BigInt(process.getegid!()));
    assert.equal(copied.mode & 0o777n, 0o700n); assert.notEqual(copied.ino, before.ino);
    await access(output, constants.R_OK | constants.W_OK);
    assert.deepEqual(await readFile(output), bytes);
    const after = await lstat(source, { bigint: true });
    for (const key of ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const)
      assert.equal(after[key], before[key]);
    assert.deepEqual(await readFile(source), bytes);
    const originalOutput = await lstat(output, { bigint: true });
    await assert.rejects(copyWritableSupervisorSeaImage(source, output), { code: 'EEXIST' });
    assert.deepEqual(await lstat(output, { bigint: true }), originalOutput);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

test('the signed server diagnostic banner preserves actual concurrent completion order and joins every producer', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  assert.equal(typeof builder.SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER, 'string');
  const bundled = await build({ stdin: { contents: `
    (async()=>{
      const {beginInstalledServerAuthentication} = require('./src/state/installed-diagnostics.ts');
      const observe = beginInstalledServerAuthentication();
      await observe('image_hash',async()=> 'private-original-value');
      const finish=[], phases=['process_cas','principal_cas','peer_cas','channel_cas'];
      const tasks=phases.map((phase,index)=>observe(phase,()=>new Promise((resolve,reject)=>{
        finish[index]=()=>index===0?reject(Error('private-original-error')):resolve('private-original-value');
      })));
      const joined=Promise.allSettled(tasks);
      for(const index of [2,0,3,1]) { finish[index](); await new Promise(resolve=>setImmediate(resolve)); }
      const results=await joined;
      if(results.length!==4 || results[0].status!=='rejected' || results.slice(1).some(row=>row.status!=='fulfilled'))
        throw Error('original producer did not join');
      process.stdout.write('original-publisher-complete');
    })();
  `, resolveDir: fileURLToPath(new URL('../../..', import.meta.url)) }, bundle: true, write: false,
  platform: 'node', format: 'cjs', banner: { js: builder.SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER as string } });
  const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'original-publisher-complete');
  const rows = child.stderr.trim().split('\n');
  assert.equal(rows.length, 6); assert.equal(rows[0], 'CLIQ_SERVER_AUTH_V1:1:publish_started:0');
  for (const [index, phase] of ['image_hash_completed','peer_cas_completed','process_cas_failed',
    'channel_cas_completed','principal_cas_completed'].entries())
    assert.match(rows[index + 1]!, new RegExp('^CLIQ_SERVER_AUTH_V1:1:' + phase + ':(0|[1-9][0-9]*)$'));
  assert(rows.every(row => Buffer.byteLength(row + '\n') <= 128));
});

test('the server diagnostic subscriber rejects malformed or private fields without getters and contains output failure', async () => {
  const { SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER } = await import('./supervisor-sea-builder.js');
  for (const closed of [false, true]) {
    const bundled = await build({ stdin: { contents: `
      const diagnostic = require('node:diagnostics_channel').channel('cliq.installed.server.authentication.v1');
      if (${closed}) require('node:fs').closeSync(2);
      let reads = 0;
      const row = {ordinal:1,phase:'image_hash_completed',elapsedNs:123};
      const privateText = 'private-request-path-key-and-error';
      for (const value of [null,[],privateText,{...row,privateText},{...row,ordinal:0},
        {...row,ordinal:9007199254740992},{...row,ordinal:'1'},{...row,elapsedNs:-1},
        {...row,elapsedNs:1.2},{...row,elapsedNs:Infinity},{...row,elapsedNs:'1'},
        {...row,elapsedNs:9007199254740992},{...row,phase:privateText},{...row,phase:['image_hash_completed']},
        {...row,phase:'publish_started',elapsedNs:1},
        Object.defineProperty({...row},'elapsedNs',{get(){reads++;throw Error(privateText)}}),
        Object.defineProperty({...row},'hidden',{value:privateText}),
        Object.assign({...row},{[Symbol('private')]:privateText}),
        new Proxy(row,{ownKeys(){reads++;throw Error(privateText)}}),
        new Proxy(row,{getOwnPropertyDescriptor(){reads++;throw Error(privateText)}}),
        new Proxy(row,{getPrototypeOf(){reads++;throw Error(privateText)}}),
        new Proxy(row,{get(){reads++;throw Error(privateText)}})]) diagnostic.publish(value);
      diagnostic.publish(row);
      process.stdout.write('original-publisher-complete:' + reads);
    ` }, bundle: true, write: false, platform: 'node', format: 'cjs',
    banner: { js: SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER } });
    const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, 'original-publisher-complete:0');
    assert.equal(child.stderr, closed ? '' : 'CLIQ_SERVER_AUTH_V1:1:image_hash_completed:123\n');
  }
});

test('the server diagnostic sink has one explicit truncation marker after its 64 fixed records', async () => {
  const { SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER } = await import('./supervisor-sea-builder.js');
  const bundled = await build({ stdin: { contents: `
    const diagnostic = require('node:diagnostics_channel').channel('cliq.installed.server.authentication.v1');
    for(let ordinal=1;ordinal<=80;ordinal++) diagnostic.publish({ordinal,phase:'publish_started',elapsedNs:0});
    process.stdout.write('original-publisher-complete');
  ` }, bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER } });
  const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'original-publisher-complete');
  const rows = child.stderr.trim().split('\n'); assert.equal(rows.length, 65);
  assert.equal(rows.at(-1), 'CLIQ_SERVER_AUTH_V1:truncated');
  assert.equal(rows[63], 'CLIQ_SERVER_AUTH_V1:64:publish_started:0');
  assert(rows.every(row => Buffer.byteLength(row + '\n') <= 128));
});

test('the publication fixture banner emits only the closed joined packet, bounded to four literal frames', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  const banner = builder.PUBLICATION_RETIREMENT_DIAGNOSTIC_BANNER;
  assert.equal(typeof banner, 'string', 'the fixed joined-publication diagnostic banner must exist');
  const key = 'a'.repeat(64);
  const packet = { version: 1, key, kind: 'namespace', joined: true,
    slots: [null, [1, 1, 'ok', '10', '20', '11', '21'], [1, 1, 'ok', '12', '22', '13', '23']] };
  const bundled = await build({ stdin: { contents: `
    require('node:diagnostics_channel').channel('cliq.installed.publication.retirement.v1').publish(${JSON.stringify(packet)});
    process.stdout.write('original-producer-complete');
  ` }, bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: banner as string } });
  const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'original-producer-complete');
  const prefix = 'CLIQ_PUBLICATION_RETIRE_V1:' + key + ':namespace:';
  assert.equal(child.stderr, prefix + '0:none\n' + prefix + '1:1:1:ok:10:20:11:21\n' +
    prefix + '2:1:1:ok:12:22:13:23\n' + prefix + 'joined\n');
  assert(child.stderr.split('\n').filter(Boolean).every(line => Buffer.byteLength(line + '\n') <= 256));
  assert(Buffer.byteLength(child.stderr) <= 1024);
});

test('publication diagnostics reject private or malformed data without getters, and contain their own output failure', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  for (const closeStderr of [false, true]) {
    const bundled = await build({ stdin: { contents: `
      const diagnostic = require('node:diagnostics_channel').channel('cliq.installed.publication.retirement.v1');
      if (${closeStderr}) require('node:fs').closeSync(2);
      let getters = 0;
      const original = {version:1,key:'a'.repeat(64),kind:'namespace',joined:true,slots:[null,
        [1,1,'ok','10','20','11','21'],[1,1,'ok','12','22','13','23']]};
      const privateText = 'private-request-and-error-text';
      for (const packet of [{...original,version:2},{...original,joined:false},
        {...original,key:privateText},{...original,privateText},{...original,slots:Array(3)},
        {...original,slots:[null,null,null]},
        {...original,slots:[null,[4294967296,4294967296,'ok','10','20','11','21'],original.slots[2]]},
        {...original,slots:[null,[1,1,'ok','10','20','9','21'],original.slots[2]]},
        {...original,slots:[null,[0,1,'ok','10','20','11','21'],original.slots[2]]},
        {...original,slots:[null,[1,0,'unavailable'],original.slots[2]]},
        {...original,slots:[null,[1,1,privateText],original.slots[2]]},
        {...original,slots:[null,[1,1,'ok','18446744073709551616','20','11','21'],original.slots[2]]},
        {...original,slots:[null,[1,1,'ok','01','20','11','21'],original.slots[2]]},
        Object.defineProperty({...original},'key',{get(){getters++;throw Error(privateText)}}),
        {...original,slots:[null,Object.defineProperty([1,1,'ok','10','20','11','21'],3,
          {get(){getters++;throw Error(privateText)}}),original.slots[2]]}]) diagnostic.publish(packet);
      if (${closeStderr}) diagnostic.publish(original);
      process.stdout.write('original-producer-complete:' + getters);
    ` }, bundle: true, write: false, platform: 'node', format: 'cjs',
    banner: { js: builder.PUBLICATION_RETIREMENT_DIAGNOSTIC_BANNER as string } });
    const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, 'original-producer-complete:0'); assert.equal(child.stderr, '');
  }
});

test('the publication diagnostic sink explicitly stops at its fixed packet cap without affecting its producer', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  const bundled = await build({ stdin: { contents: `
    const diagnostic = require('node:diagnostics_channel').channel('cliq.installed.publication.retirement.v1');
    for(let i=0;i<40;i++) diagnostic.publish({version:1,key:'b'.repeat(64),kind:'original',joined:true,
      slots:[null,[1,1,'unavailable'],[1,1,'ok','1','2','3','4']]});
    process.stdout.write('original-producer-complete');
  ` }, bundle: true, write: false, platform: 'node', format: 'cjs',
  banner: { js: builder.PUBLICATION_RETIREMENT_DIAGNOSTIC_BANNER as string } });
  const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'original-producer-complete');
  const lines = child.stderr.trim().split('\n'); assert.equal(lines.length, 129);
  assert.equal(lines.at(-1), 'CLIQ_PUBLICATION_RETIRE_V1:truncated');
  assert(lines.every(line => Buffer.byteLength(line + '\n') <= 256));
});

test('publication tuple length comes from copied metadata without reading an array property', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  const bundled = await build({ stdin: { contents: `
    let reads = 0;
    const span = new Proxy([1,1,'ok','10','20','11','21'], {
      get(target,key,receiver) { reads++; return Reflect.get(target,key,receiver); }
    });
    require('node:diagnostics_channel').channel('cliq.installed.publication.retirement.v1')
      .publish({version:1,key:'a'.repeat(64),kind:'original',joined:true,
        slots:[null,span,[1,1,'ok','12','22','13','23']]});
    process.stdout.write('property-reads:' + reads);
  ` }, bundle: true, write: false, platform: 'node', format: 'cjs',
  banner: { js: builder.PUBLICATION_RETIREMENT_DIAGNOSTIC_BANNER as string } });
  const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'property-reads:0');
  assert.equal(child.stderr.split('\n').filter(Boolean).length, 4);
});

test('carrier preparation refuses an existing extraction directory without adopting or changing it', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-existing-carrier-'));
  try {
    const name = `node-v${SUPERVISOR_SEA_NODE_VERSION}-${process.platform}-${process.arch}`;
    const nodeRoot = path.join(fixture, name);
    await mkdir(nodeRoot, { mode: 0o700 });
    const sentinel = path.join(nodeRoot, 'existing-data');
    await writeFile(sentinel, 'existing carrier directory must remain untouched\n', { flag: 'wx', mode: 0o400 });
    const rootBefore = await lstat(nodeRoot, { bigint: true });
    const fileBefore = await lstat(sentinel, { bigint: true });
    // Existing local source is deliberately not an archive. The fresh-root
    // precondition must refuse before reading it, downloading, or extracting.
    await assert.rejects(prepareSupervisorSeaCarrier(fixture, fileURLToPath(import.meta.url)),
      /carrier extraction directory must not already exist/);
    assert.deepEqual(await lstat(nodeRoot, { bigint: true }), rootBefore);
    assert.deepEqual(await lstat(sentinel, { bigint: true }), fileBefore);
    assert.equal(await readFile(sentinel, 'utf8'), 'existing carrier directory must remain untouched\n');
    assert.deepEqual(await readdir(fixture), [name]);
    assert.deepEqual(await readdir(nodeRoot), ['existing-data']);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

test('installed publisher preparation preserves the original fresh-root refusal before any derivation', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  assert.equal(typeof builder.prepareInstalledSupervisorSeaCarrier, 'function');
  const prepare = builder.prepareInstalledSupervisorSeaCarrier as typeof prepareSupervisorSeaCarrier;
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-carrier-'));
  try {
    const name = `node-v${SUPERVISOR_SEA_NODE_VERSION}-${process.platform}-${process.arch}`;
    const nodeRoot = path.join(fixture, name); await mkdir(nodeRoot, { mode: 0o700 });
    const sentinel = path.join(nodeRoot, 'existing-data');
    await writeFile(sentinel, 'not a publisher input\n', { flag: 'wx', mode: 0o400 });
    const before = await lstat(sentinel, { bigint: true });
    await assert.rejects(prepare(fixture, fileURLToPath(import.meta.url)), /carrier extraction directory must not already exist/);
    assert.deepEqual(await lstat(sentinel, { bigint: true }), before);
    assert.equal(await readFile(sentinel, 'utf8'), 'not a publisher input\n');
    assert.deepEqual(await readdir(fixture), [name]);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

test('carrier derivation creates a fresh private child in either private or read-only-traversable publisher fixtures', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  assert.equal(typeof builder.createSupervisorCarrierDerivationDirectory, 'function');
  const create = builder.createSupervisorCarrierDerivationDirectory as (fixture: string) => Promise<string>;
  for (const mode of [0o700, 0o755]) {
    const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-carrier-parent-'));
    try {
      await chmod(fixture, mode);
      const original = path.join(fixture, 'original-carrier');
      await writeFile(original, 'unchanged original carrier fixture\n', { flag: 'wx', mode: 0o500 });
      const before = await lstat(original, { bigint: true });
      const directory = await create(fixture);
      assert.equal(directory, path.join(fixture, 'supervisor-carrier-build'));
      assert.deepEqual(await readdir(directory), []);
      const child = await lstat(directory, { bigint: true });
      assert(child.isDirectory()); assert.equal(child.mode & 0o777n, 0o700n);
      assert.equal(child.uid, BigInt(process.geteuid!()));
      assert.equal((await lstat(fixture)).mode & 0o777, mode);
      assert.deepEqual(await lstat(original, { bigint: true }), before);
      assert.equal(await readFile(original, 'utf8'), 'unchanged original carrier fixture\n');
      await assert.rejects(create(fixture), { code: 'EEXIST' });
      assert.deepEqual(await lstat(directory, { bigint: true }), child);
    } finally { await rm(fixture, { recursive: true, force: true }); }
  }
});

test('carrier derivation refuses writable publisher fixtures before creating any child', async () => {
  const builder = await import('./supervisor-sea-builder.js') as Record<string, unknown>;
  assert.equal(typeof builder.createSupervisorCarrierDerivationDirectory, 'function');
  const create = builder.createSupervisorCarrierDerivationDirectory as (fixture: string) => Promise<string>;
  for (const mode of [0o720, 0o702, 0o777]) {
    const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-carrier-writable-'));
    try {
      await chmod(fixture, mode);
      await assert.rejects(create(fixture), /protected publisher fixture/);
      assert.deepEqual(await readdir(fixture), []);
      assert.equal((await lstat(fixture)).mode & 0o777, mode);
    } finally { await rm(fixture, { recursive: true, force: true }); }
  }
});

test('carrier derivation never adopts a pre-existing file or symlink and refuses a symlinked parent', async () => {
  const { createSupervisorCarrierDerivationDirectory: create } = await import('./supervisor-sea-builder.js');
  for (const kind of ['file', 'symlink'] as const) {
    const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-carrier-existing-'));
    try {
      const target = path.join(fixture, 'existing-target'); await mkdir(target, { mode: 0o700 });
      const sentinel = path.join(target, 'sentinel'); await writeFile(sentinel, 'original\n', { flag: 'wx', mode: 0o400 });
      const child = path.join(fixture, 'supervisor-carrier-build');
      if (kind === 'file') await writeFile(child, 'not a directory\n', { flag: 'wx', mode: 0o400 });
      else await symlink(target, child);
      const before = await lstat(child, { bigint: true });
      await assert.rejects(create(fixture), { code: 'EEXIST' });
      assert.deepEqual(await lstat(child, { bigint: true }), before);
      const alias = path.join(fixture, 'parent-alias'); await symlink(target, alias);
      await assert.rejects(create(alias));
      assert.deepEqual(await readdir(target), ['sentinel']);
      assert.equal(await readFile(sentinel, 'utf8'), 'original\n');
    } finally { await rm(fixture, { recursive: true, force: true }); }
  }
});

// Actual diagnostic code generation and Node channel execution only. This does
// not replace the installed image's credential, manager or native qualification.
test('the fixed fixture banner writes only known credential phase markers and contains its own output errors', async () => {
  for (const closeStderr of [false, true]) {
    const bundled = await build({ stdin: { contents: `
      import { channel } from 'node:diagnostics_channel';
      import { closeSync } from 'node:fs';
      import { INSTALLED_CREDENTIAL_PHASE_CHANNEL, INSTALLED_CREDENTIAL_PHASES, noteInstalledCredentialPhase }
        from './src/state/installed-diagnostics.ts';
      if (${closeStderr}) closeSync(2);
      for (const phase of INSTALLED_CREDENTIAL_PHASES) noteInstalledCredentialPhase(phase);
      channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL).publish('untrusted-private-value');
      channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL).publish(Object.defineProperty({}, 'phase', {
        get() { throw new Error('must not inspect untrusted properties'); }
      }));
      process.stdout.write('diagnostic-only-complete');
    `, resolveDir: fileURLToPath(new URL('../../..', import.meta.url)) },
    bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: CREDENTIAL_PHASE_DIAGNOSTIC_BANNER } });
    const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, 'diagnostic-only-complete');
    assert.equal(child.stderr, closeStderr ? '' : ['open_selected', 'history', 'first_supervisor', 'secret_input',
      'second_supervisor', 'platform_store', 'finalize', 'retire'].map(phase => `CLIQ_CREDENTIAL_PHASE_V1:${phase}\n`).join(''));
  }
});

test('the work banner emits only bounded fixed counters and catches its own closed-pipe errors', async () => {
  for (const closeStderr of [false, true]) {
    const bundled = await build({ stdin: { contents: `
      import { channel } from 'node:diagnostics_channel';
      import { closeSync } from 'node:fs';
      import { INSTALLED_WORK_CHANNEL, observeInstalledWork, noteInstalledWorkRead }
        from './src/state/installed-work-diagnostics.ts';
      if (${closeStderr}) closeSync(2);
      const work = channel(INSTALLED_WORK_CHANNEL);
      work.publish('private-unrecognized-content');
      work.publish(Object.defineProperty({}, 'package', {get(){throw new Error('must not call getters')}}));
      (async()=>{ await observeInstalledWork('package', async()=>{noteInstalledWorkRead(7)});
        process.stdout.write('diagnostic-only-complete') })();
    `, resolveDir: fileURLToPath(new URL('../../..', import.meta.url)) },
    bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: INSTALLED_WORK_DIAGNOSTIC_BANNER } });
    const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text, '--', 'fixed-image', '--installed-credential'],
      { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, 'diagnostic-only-complete');
    if (closeStderr) assert.equal(child.stderr, '');
    else {
      const rows = child.stderr.trim().split('\n'); assert.equal(rows.length, 2);
      assert(rows.every(row => row.length < 256 && /^CLIQ_INSTALLED_WORK_V1:credential:(?:0|[1-9][0-9]*)(?::(?:0|[1-9][0-9]*)){11}$/u.test(row)));
      const final = rows.at(-1)!.split(':').slice(2).map(Number);
      assert.deepEqual(final.slice(0, 3), [1, 1, 7]); assert.deepEqual(final.slice(4), Array(8).fill(0));
      assert(!child.stderr.includes('private-unrecognized-content'));
    }
  }
});

test('the trusted work subscriber caps output and explicitly reports truncation instead of rounding or emitting arbitrary data', async () => {
  const bundled = await build({ stdin: { contents: `
    import { channel } from 'node:diagnostics_channel';
    import { INSTALLED_WORK_CHANNEL, observeInstalledWork } from './src/state/installed-work-diagnostics.ts';
    const diagnostic = channel(INSTALLED_WORK_CHANNEL);
    const zero = {started:0,completed:0,bytesRead:0,spanElapsedMs:0};
    for (const row of [{...zero,started:NaN},{...zero,started:-1},{...zero,completed:1},
      {...zero,bytesRead:Number.MAX_SAFE_INTEGER+1}])
      diagnostic.publish({package:row,revalidate:zero,createCompare:zero});
    diagnostic.publish({package:zero,revalidate:zero,createCompare:{...zero,bytesRead:1}});
    (async()=>{for(let i=0;i<140;i++)await observeInstalledWork('revalidate',async()=>{});
      process.stdout.write('original-work-complete')})();
  `, resolveDir: fileURLToPath(new URL('../../..', import.meta.url)) },
  bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: INSTALLED_WORK_DIAGNOSTIC_BANNER } });
  const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text, '--', 'fixed-image', '--bootstrap-credential'],
    { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'original-work-complete');
  const lines = child.stderr.trim().split('\n'); assert.equal(lines.length, 257);
  assert.equal(lines.at(-1), 'CLIQ_INSTALLED_WORK_V1:bootstrap:truncated');
  assert(lines.every(line => line.length < 256));
});
