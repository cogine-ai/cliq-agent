// Actual fixed native image + supplied Node SQLite API. Not signed-install or key-store qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

test('original-root native credential scope uses one SQLite image and healthy generations invalidate old tokens', { timeout: 180000 }, async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-native-'));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const helper = path.join(fixture, 'state-owner.node');
    const source = fileURLToPath(new URL('../../../native/state-owner/state-owner.c', import.meta.url));
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
      ...(process.platform === 'darwin' ? ['-dynamiclib', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC']),
      '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), source, '-o', helper],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(compiled.error, undefined); assert.equal(compiled.status, 0, compiled.stderr);
    const symbols = spawnSync(process.platform === 'darwin' ? 'nm' : 'readelf',
      process.platform === 'darwin' ? ['-m', helper] : ['--dyn-syms', '--wide', helper], { encoding: 'utf8', timeout: 10000 });
    assert.equal(symbols.error, undefined); assert.equal(symbols.status, 0, symbols.stderr);
    if (process.platform === 'darwin') assert.match(symbols.stdout.split('\n').find(line => /\b_sqlite3_api$/u.test(line)) ?? '',
      /(?:private external |non-external \(was a private external\) )_sqlite3_api\b/u);
    else assert.doesNotMatch(symbols.stdout, /\bsqlite3_api\b/u);
    assert.match(symbols.stdout, /\bsqlite3_cliqcredentialvfs_init\b|\b_sqlite3_cliqcredentialvfs_init\b/u);
    const threadHelper = path.join(fixture, 'state-owner-thread-guard.node');
    const threadSource = fileURLToPath(new URL('credential-authority-thread-probe.c', import.meta.url));
    const threadCompiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
      ...(process.platform === 'darwin' ? ['-dynamiclib', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC']),
      '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), threadSource, '-o', threadHelper],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(threadCompiled.error, undefined); assert.equal(threadCompiled.status, 0, threadCompiled.stderr);
    const threadGuard = spawnSync(carrier.carrier, ['--no-warnings', '-e',
      `const loaded={exports:{}};process.dlopen(loaded,${JSON.stringify(threadHelper)});`], { encoding: 'utf8', timeout: 10000 });
    assert.equal(threadGuard.error, undefined); assert.equal(threadGuard.signal, null);
    assert.equal(threadGuard.status, 0, threadGuard.stderr);
    assert.match(threadGuard.stderr, /CLIQ_CREDENTIAL_FOREIGN_THREAD_GUARD_VERIFIED/u);
    const root = path.join(fixture, 'root');
    await mkdir(path.join(root, 'runtime'), { recursive: true, mode: 0o700 });
    await chmod(root, 0o700); await chmod(path.join(root, 'runtime'), 0o700);
    const canonicalRoot = await realpath(root);
    const lifetimeProbe = path.join(fixture, 'producer-lifetime-probe');
    if (process.platform === 'linux') {
      const lifetimeSource = fileURLToPath(new URL('credential-producer-lifetime-probe.c', import.meta.url));
      const lifetimeCompiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', lifetimeSource, '-o', lifetimeProbe],
        { encoding: 'utf8', timeout: 60000 });
      assert.equal(lifetimeCompiled.error, undefined); assert.equal(lifetimeCompiled.status, 0, lifetimeCompiled.stderr);
    }
    const child = spawnSync(carrier.carrier, ['--no-warnings', '--expose-gc', '-e', `
      (async()=>{
      const assert = require('node:assert/strict');
      const fs = require('node:fs');
      const {DatabaseSync} = require('node:sqlite');
      const loaded = {exports:{}}; process.dlopen(loaded, ${JSON.stringify(helper)});
      const native = loaded.exports;
      const root = ${JSON.stringify(canonicalRoot)};
      const fd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const s = fs.fstatSync(fd, {bigint:true}); const tuple = [s.dev,s.ino,s.uid,s.gid,s.mode];
      assert.throws(() => native.acquireCredentialScope(fd, root, [s.dev,s.ino+1n,s.uid,s.gid,s.mode]), /identity/);
      assert.throws(() => native.acquireCredentialScope(fd, root, tuple, 'forbidden'), /identity/);
      assert.equal(fs.existsSync(root+'/credentials'),false);
      const a = native.acquireCredentialScope(fd, root, tuple);
      assert.equal(typeof a.generation, 'string'); a.assertHeld();
      if (process.platform === 'linux') {
        assert.equal(a.observeProducerLifetime(process.pid,process.geteuid(),native.processStartToken()),'present');
        assert.throws(()=>a.observeProducerLifetime.call({},process.pid,process.geteuid(),native.processStartToken()),/invalid/);
        for (const invalid of ['', 'unknown', 'linux-proc-start-ticks:0', 'linux-proc-start-ticks:01', native.processStartToken()+'\\0extra'])
          assert.throws(()=>a.observeProducerLifetime(process.pid,process.geteuid(),invalid),e=>e.code==='ERR_CLIQ_CREDENTIAL_PROCESS_IDENTITY');
        for (const invalid of [0,-1,1.5,NaN,Infinity,2**32+process.pid])
          assert.throws(()=>a.observeProducerLifetime(invalid,process.geteuid(),native.processStartToken()),e=>e.code==='ERR_CLIQ_CREDENTIAL_PROCESS_IDENTITY');
        assert.throws(()=>a.observeProducerLifetime(process.pid,process.geteuid()+1,native.processStartToken()),e=>e.code==='ERR_CLIQ_CREDENTIAL_PROCESS_IDENTITY');
        const producer=require('node:child_process').spawn(${JSON.stringify(lifetimeProbe)},[],{stdio:['pipe','pipe','pipe']});
        const lines=require('node:readline').createInterface({input:producer.stdout})[Symbol.asyncIterator]();
        const joined=new Promise((resolve,reject)=>{producer.once('error',reject);producer.once('close',(code,signal)=>resolve({code,signal}));});
        void joined.catch(()=>{});const watchdog=setTimeout(()=>producer.kill('SIGKILL'),5000);
        try {
          const live=(await lines.next()).value;assert.match(live,/^LIVE [1-9]\\d*$/);const pid=Number(live.split(' ')[1]);
          const stat=fs.readFileSync('/proc/'+pid+'/stat','utf8');
          const token='linux-proc-start-ticks:'+stat.slice(stat.lastIndexOf(')')+2).trim().split(/\\s+/)[19];
          assert.equal(a.observeProducerLifetime(pid,process.geteuid(),token),'present');
          producer.stdin.write('k');assert.equal((await lines.next()).value,'ZOMBIE');
          assert.equal(fs.readFileSync('/proc/'+pid+'/stat','utf8').slice(stat.lastIndexOf(')')+2).split(' ')[0],'Z');
          assert.equal(a.observeProducerLifetime(pid,process.geteuid(),token),'present','zombie is still the original lifetime');
          producer.stdin.write('r');assert.equal((await lines.next()).value,'REAPED');assert.deepEqual(await joined,{code:0,signal:null});
          assert.equal(a.observeProducerLifetime(pid,process.geteuid(),token),'dead','real reap supplies positive kernel absence');
        } finally {clearTimeout(watchdog);if(producer.exitCode===null&&producer.signalCode===null)producer.kill('SIGKILL');await joined;}
      }
      assert.throws(() => a.assertHeld.call({}), /invalid/);
      assert.throws(() => a.close('forbidden'), /invalid/);
      assert.throws(() => native.acquireCredentialScope(fd, root, tuple), /active|acquir|scope/);
      const bootstrap = new DatabaseSync(':memory:', {allowExtension:true});
      bootstrap.loadExtension(${JSON.stringify(helper)}, 'sqlite3_cliqcredentialvfs_init');
      bootstrap.enableLoadExtension(false); bootstrap.close();
      const {Worker}=require('node:worker_threads');
      const foreign=new Worker(\`
        const assert=require('node:assert/strict'),fs=require('node:fs'),{workerData}=require('node:worker_threads'),{DatabaseSync}=require('node:sqlite');
        const loaded={exports:{}};process.dlopen(loaded,workerData.helper);
        const fd=fs.openSync(workerData.root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW),s=fs.fstatSync(fd,{bigint:true});
        assert.throws(()=>loaded.exports.acquireCredentialScope(fd,workerData.root,[s.dev,s.ino,s.uid,s.gid,s.mode]),/scope|thread/);fs.closeSync(fd);
        const bootstrap=new DatabaseSync(':memory:',{allowExtension:true});
        assert.throws(()=>bootstrap.loadExtension(workerData.helper,'sqlite3_cliqcredentialvfs_init'),/initializ|error/);bootstrap.close();
        assert.throws(()=>new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-v1'),/open/);
      \`,{eval:true,workerData:{helper:${JSON.stringify(helper)},root}});
      await new Promise((resolve,reject)=>{foreign.once('error',reject);foreign.once('exit',code=>code===0?resolve():reject(new Error('foreign worker exit '+code)));});
      a.assertHeld();
      const open = () => { const db = new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-v1', {allowExtension:false});
        assert.equal(db.prepare('PRAGMA locking_mode=EXCLUSIVE').get().locking_mode,'exclusive');
        db.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA synchronous=FULL');
        assert.equal(db.prepare('PRAGMA journal_mode=WAL').get().journal_mode,'wal'); return db; };
      const first = open(); first.exec("CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES ('held-original')");
      assert.throws(() => a.close(), /live|open/); a.assertHeld(); first.close(); a.close();
      assert.throws(() => a.assertHeld(), /closed|retired|inactive/);
      assert.throws(() => a.observeProducerLifetime(process.pid,0,native.processStartToken()), /closed|retired|inactive/);
      assert.throws(() => a.close(), /closed|retired|inactive/);
      fs.fstatSync(fd);
      const b = native.acquireCredentialScope(fd, root, tuple); assert.notEqual(a.generation,b.generation);
      assert.throws(() => a.assertHeld(), /closed|retired|inactive/); b.assertHeld();
      const second = open(); assert.equal(second.prepare('SELECT value FROM proof').get().value,'held-original');
      assert.equal(second.prepare('PRAGMA integrity_check').get().integrity_check,'ok'); second.close(); b.close();
      let held = native.acquireCredentialScope(fd, root, tuple); const weak = new WeakRef(held); const third = open(); held = null;
      await new Promise(resolve=>setImmediate(resolve));
      global.gc(); global.gc();
      await new Promise(resolve=>setImmediate(resolve));
      assert(weak.deref(),'native strong owner must survive GC while SQLite uses the exact context');
      assert.equal(third.prepare('SELECT value FROM proof').get().value,'held-original');
      const contender = require('node:child_process').spawnSync(process.execPath,['--no-warnings','-e',
        'const assert=require("node:assert/strict"),fs=require("node:fs");const loaded={exports:{}};process.dlopen(loaded,'+JSON.stringify(${JSON.stringify(helper)})+');'+
        'const root='+JSON.stringify(root)+';const fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);const s=fs.fstatSync(fd,{bigint:true});'+
        'assert.throws(()=>loaded.exports.acquireCredentialScope(fd,root,[s.dev,s.ino,s.uid,s.gid,s.mode]),e=>e.code==="ERR_CLIQ_CREDENTIAL_BUSY");fs.closeSync(fd);'],
        {encoding:'utf8',timeout:5000});
      assert.equal(contender.error,undefined); assert.equal(contender.signal,null); assert.equal(contender.status,0,contender.stderr);
      third.close(); weak.deref().close(); global.gc();
      const fourth = native.acquireCredentialScope(fd,root,tuple); fourth.assertHeld(); fourth.close();
      assert.throws(() => new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-v1'), /open|fence|scope/);
      fs.closeSync(fd);
      })().catch(error=>{console.error(error);process.exitCode=1;});
    `], { encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    const gateHolder = path.join(fixture, 'global-gate-holder');
    const gateSource = fileURLToPath(new URL('credential-global-gate-holder.c', import.meta.url));
    const gateCompiled = spawnSync('cc', ['-std=c11', '-Wall', '-Wextra', '-Werror', gateSource, '-o', gateHolder],
      { encoding: 'utf8', timeout: 60000 });
    assert.equal(gateCompiled.error, undefined); assert.equal(gateCompiled.status, 0, gateCompiled.stderr);
    const retirementHelper = path.join(fixture, 'state-owner-retirement.node');
    const retirementSource = fileURLToPath(new URL('credential-authority-retirement-probe.c', import.meta.url));
    const retirementCompiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
      ...(process.platform === 'darwin' ? ['-dynamiclib', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC']),
      '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), retirementSource, '-o', retirementHelper],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(retirementCompiled.error, undefined); assert.equal(retirementCompiled.status, 0, retirementCompiled.stderr);
    for (const heldRole of ['credential', 'global']) {
      const busyRoot = path.join(fixture, `busy-${heldRole}`);
      await mkdir(path.join(busyRoot, 'runtime'), { recursive: true, mode: 0o700 });
      await chmod(busyRoot, 0o700); await chmod(path.join(busyRoot, 'runtime'), 0o700);
      const canonical = await realpath(busyRoot);
      const holdingScript = `
        const fs = require('node:fs'); const loaded={exports:{}}; process.dlopen(loaded, ${JSON.stringify(helper)});
        const root=${JSON.stringify(canonical)}; const fd=fs.openSync(root, fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
        const s=fs.fstatSync(fd,{bigint:true}); const scope=loaded.exports.acquireCredentialScope(fd,root,[s.dev,s.ino,s.uid,s.gid,s.mode]);
        process.stdout.write('READY\\n'); process.stdin.once('data',()=>{scope.close();fs.closeSync(fd);process.stdin.destroy();});
        setTimeout(()=>process.exit(97),12000).unref();
      `;
      const busy = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
        (async()=>{
          const assert=require('node:assert/strict'), fs=require('node:fs'), {spawn}=require('node:child_process');
          const loaded={exports:{}}; process.dlopen(loaded, ${JSON.stringify(helper)}); const native=loaded.exports;
          const root=${JSON.stringify(canonical)}; const fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
          const s=fs.fstatSync(fd,{bigint:true}), tuple=[s.dev,s.ino,s.uid,s.gid,s.mode];
          const holder=${JSON.stringify(heldRole)}==='global' ? spawn(${JSON.stringify(gateHolder)},[],{env:{...process.env,HOME:root}})
            : spawn(process.execPath,['--no-warnings','-e',${JSON.stringify(holdingScript)}]);
          let output='', errors=''; const joined=new Promise((resolve,reject)=>{holder.once('error',reject);holder.once('close',(code,signal)=>resolve({code,signal}));});
          void joined.catch(()=>{}); const ready=new Promise((resolve,reject)=>{
            holder.once('error',reject); holder.once('close',()=>reject(new Error('holder exited before barrier: '+errors)));
            holder.stderr.on('data',chunk=>{errors+=chunk; if(errors.length>65536)reject(new Error('stderr bound'));});
            holder.stdout.on('data',chunk=>{output+=chunk; if(output.length>65536)reject(new Error('stdout bound'));if(output.includes('\\n')){if(output.trim()==='READY')resolve();else reject(new Error('unexpected ready barrier'));}});
          });
          const watchdog=setTimeout(()=>holder.kill('SIGKILL'),12000);
          try { await ready;
            assert.throws(()=>native.acquireCredentialScope(fd,root,tuple),error=>error.code==='ERR_CLIQ_CREDENTIAL_BUSY');
            if(${JSON.stringify(heldRole)}==='global') assert.equal(fs.existsSync(root+'/credentials'),false,'exclusive gate must block before credential/data creation');
            holder.stdin.end('\\n'); const exit=await joined; assert.equal(exit.code,0,errors);assert.equal(exit.signal,null);
            const recovered=native.acquireCredentialScope(fd,root,tuple); recovered.assertHeld(); recovered.close(); fs.fstatSync(fd);fs.closeSync(fd);
          } finally {clearTimeout(watchdog);if(holder.exitCode===null&&holder.signalCode===null)holder.kill('SIGKILL');await joined;}
        })().catch(error=>{console.error(error);process.exitCode=1;});
      `], { encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
      assert.equal(busy.error, undefined); assert.equal(busy.signal, null); assert.equal(busy.status, 0, busy.stderr);
    }
    const cleanupRoot = path.join(fixture, 'uncertain-cleanup');
    await mkdir(path.join(cleanupRoot, 'runtime'), { recursive: true, mode: 0o700 });
    await chmod(cleanupRoot, 0o700); await chmod(path.join(cleanupRoot, 'runtime'), 0o700);
    const cleanupCanonical = await realpath(cleanupRoot);
    const cleanupHolder = `
      const fs=require('node:fs'), loaded={exports:{}};process.dlopen(loaded,${JSON.stringify(helper)});
      const root=${JSON.stringify(cleanupCanonical)},fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
      const s=fs.fstatSync(fd,{bigint:true}),scope=loaded.exports.acquireCredentialScope(fd,root,[s.dev,s.ino,s.uid,s.gid,s.mode]);
      process.stdout.write('READY\\n');process.stdin.once('data',()=>{scope.close();fs.closeSync(fd);process.stdin.destroy();});setTimeout(()=>process.exit(97),12000).unref();
    `;
    const cleanup = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
      (async()=>{
        const assert=require('node:assert/strict'),fs=require('node:fs'),{spawn}=require('node:child_process');
        const loaded={exports:{}};process.dlopen(loaded,${JSON.stringify(retirementHelper)});const native=loaded.exports;
        const root=${JSON.stringify(cleanupCanonical)},fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
        const s=fs.fstatSync(fd,{bigint:true}),tuple=[s.dev,s.ino,s.uid,s.gid,s.mode];
        const holder=spawn(process.execPath,['--no-warnings','-e',${JSON.stringify(cleanupHolder)}],{env:{...process.env,CLIQ_CREDENTIAL_RETIREMENT_ROLE:''}});
        let errors='',output='';const joined=new Promise((resolve,reject)=>{holder.once('error',reject);holder.once('close',(code,signal)=>resolve({code,signal}));});void joined.catch(()=>{});
        const ready=new Promise((resolve,reject)=>{holder.once('error',reject);holder.once('close',()=>reject(new Error(errors)));holder.stderr.on('data',x=>errors+=x);holder.stdout.on('data',x=>{output+=x;if(output==='READY\\n')resolve();});});
        const watchdog=setTimeout(()=>holder.kill('SIGKILL'),12000);
        try {await ready;assert.throws(()=>native.acquireCredentialScope(fd,root,tuple),error=>error.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
          assert.throws(()=>native.acquireCredentialScope(fd,root,tuple),/uncertain/);fs.fstatSync(fd);
          holder.stdin.end('\\n');const exit=await joined;assert.equal(exit.code,0,errors);assert.equal(exit.signal,null);fs.closeSync(fd);
        } finally {clearTimeout(watchdog);if(holder.exitCode===null&&holder.signalCode===null)holder.kill('SIGKILL');await joined;}
      })().catch(error=>{console.error(error);process.exitCode=1;});
    `], { env: { ...process.env, CLIQ_CREDENTIAL_RETIREMENT_ROLE: 'root' }, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
    assert.equal(cleanup.error, undefined); assert.equal(cleanup.signal, null); assert.equal(cleanup.status, 0, cleanup.stderr);
    assert.match(cleanup.stderr, /CLIQ_CREDENTIAL_RETIREMENT_VERIFIED/u);
    for (const role of ['journal', 'wal', 'credentials', 'root', 'main', 'lock', 'runtime', 'global']) {
      const failureRoot = path.join(fixture, `retirement-${role}`);
      await mkdir(path.join(failureRoot, 'runtime'), { recursive: true, mode: 0o700 });
      await chmod(failureRoot, 0o700); await chmod(path.join(failureRoot, 'runtime'), 0o700);
      const canonical = await realpath(failureRoot);
      const failed = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
        const assert=require('node:assert/strict'),fs=require('node:fs'),{DatabaseSync}=require('node:sqlite');
        const loaded={exports:{}};process.dlopen(loaded,${JSON.stringify(retirementHelper)});const native=loaded.exports;
        const root=${JSON.stringify(canonical)},fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
        const s=fs.fstatSync(fd,{bigint:true}),tuple=[s.dev,s.ino,s.uid,s.gid,s.mode],scope=native.acquireCredentialScope(fd,root,tuple);
        const bootstrap=new DatabaseSync(':memory:',{allowExtension:true});bootstrap.loadExtension(${JSON.stringify(retirementHelper)},'sqlite3_cliqcredentialvfs_init');bootstrap.enableLoadExtension(false);bootstrap.close();
        const db=new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-v1',{allowExtension:false});
        db.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA synchronous=FULL');assert.equal(db.prepare('PRAGMA journal_mode=WAL').get().journal_mode,'wal');
        db.exec('CREATE TABLE proof(value INTEGER); INSERT INTO proof VALUES (47)');db.close();
        assert.throws(()=>scope.close(),error=>error.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
        assert.throws(()=>scope.close(),error=>error.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
        assert.throws(()=>scope.assertHeld(),/uncertain|changed/);
        assert.throws(()=>native.acquireCredentialScope(fd,root,tuple),/active|uncertain/);
        assert.throws(()=>new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-v1'),/open/);
        fs.fstatSync(fd);fs.closeSync(fd);
        // Fixed test wrapper proves consumption order, later original inodes,
        // and live reused /dev/zero FD at exit. It claims no post-EIO lock.
      `], { env: { ...process.env, CLIQ_CREDENTIAL_RETIREMENT_ROLE: role }, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
      assert.equal(failed.error, undefined); assert.equal(failed.signal, null); assert.equal(failed.status, 0, `${role}: ${failed.stderr}`);
      assert.match(failed.stderr, /CLIQ_CREDENTIAL_RETIREMENT_VERIFIED/u);
    }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
