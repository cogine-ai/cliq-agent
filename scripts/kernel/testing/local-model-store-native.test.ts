// Actual original-FD store and supplied Node SQLite API in an explicitly
// provisioned disposable NSS account. No signed engine, Run admission,
// activation, no-egress or physical service recovery is claimed here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

test('managed model data store retains original account/store/pager ownership and joins bounded immutable imports', { timeout: 180000 }, async () => {
  const account = os.userInfo();
  assert.equal(process.platform, 'linux');
  assert.equal(process.env.CLIQ_DISPOSABLE_ACCOUNT_QUALIFICATION, '1', 'the actual disposable-account campaign is required');
  assert.equal(account.username, 'cliq-kernel-gate-test');
  assert.equal(account.homedir, '/home/cliq-kernel-gate-test');
  assert.ok(account.uid >= 1000); assert.equal(account.uid, process.geteuid?.());
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-local-model-native-'));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const helper = path.join(fixture, 'state-owner.node');
    const source = fileURLToPath(new URL('../../../native/state-owner/state-owner.c', import.meta.url));
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
      '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), source, '-o', helper],
    { encoding: 'utf8', timeout: 60000, maxBuffer: 262144 });
    assert.equal(compiled.error, undefined); assert.equal(compiled.status, 0, compiled.stderr);
    const symbols = spawnSync('readelf', ['--dyn-syms', '--wide', helper], { encoding: 'utf8', timeout: 10000 });
    assert.equal(symbols.error, undefined); assert.equal(symbols.status, 0, symbols.stderr);
    assert.doesNotMatch(symbols.stdout, /\bsqlite3_api\b/u);
    assert.match(symbols.stdout, /\bsqlite3_cliqlocalmodelvfs_init\b/u);
    const root = path.join(fixture, 'root'); await mkdir(root, { mode: 0o700 }); await chmod(root, 0o700);
    const canonicalRoot = await realpath(root);
    const child = spawnSync(carrier.carrier, ['--no-warnings', '--expose-gc', '-e', `
      (async () => {
        const assert=require('node:assert/strict'), fs=require('node:fs'), path=require('node:path');
        const {createHash}=require('node:crypto'), {DatabaseSync}=require('node:sqlite');
        const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
        const loaded={exports:{}}; process.dlopen(loaded,${JSON.stringify(helper)}); const native=loaded.exports;
        const root=${JSON.stringify(canonicalRoot)};
        const fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
        const identity=fs.fstatSync(fd,{bigint:true}), tuple=[identity.dev,identity.ino,identity.uid,identity.gid,identity.mode];
        assert.throws(()=>native.acquireLocalModelStore(fd,root,[identity.dev,identity.ino+1n,identity.uid,identity.gid,identity.mode]),/refused/);
        assert.equal(fs.existsSync(root+'/local-models'),false);
        const exclusive=native.acquireKernelGlobalExclusive();
        assert.throws(()=>native.acquireLocalModelStore(fd,root,tuple),e=>e.code==='ERR_CLIQ_LOCAL_MODEL_BUSY');
        assert.equal(fs.existsSync(root+'/local-models'),false); exclusive.close();
        assert.throws(()=>native.acquireLocalModelStore(fd,root,tuple,{}),/refused/);
        const store=native.acquireLocalModelStore(fd,root,tuple); store.assertHeld();
        assert.throws(()=>native.acquireLocalModelStore(fd,root,tuple),/active/);
        assert.throws(()=>store.assertHeld.call({}),/holder/);
        const bootstrap=new DatabaseSync(':memory:',{allowExtension:true});
        bootstrap.loadExtension(${JSON.stringify(helper)},'sqlite3_cliqlocalmodelvfs_init'); bootstrap.enableLoadExtension(false); bootstrap.close();
        const uri='file:cliq-local-model-registry?vfs=cliq-local-model-store-v1';
        let db=new DatabaseSync(uri,{allowExtension:false});
        assert.equal(db.prepare('PRAGMA database_list').get().file,'/cliq-local-model-registry');
        db.exec('PRAGMA locking_mode=EXCLUSIVE;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;PRAGMA temp_store=MEMORY;PRAGMA mmap_size=0');
        db.exec('CREATE TABLE model_registry(owner TEXT PRIMARY KEY,head TEXT NOT NULL) STRICT');
        db.prepare('INSERT INTO model_registry VALUES(?,?)').run('original','head-1');
        db.exec('BEGIN IMMEDIATE');db.prepare('UPDATE model_registry SET head=? WHERE owner=?').run('head-2','original');db.exec('ROLLBACK');
        assert.equal(db.prepare('SELECT head FROM model_registry').get().head,'head-1');
        assert.throws(()=>store.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
        assert.throws(()=>new DatabaseSync(uri,{allowExtension:false}),e=>e.code==='ERR_SQLITE_ERROR'&&e.errcode===5);
        db.close();store.assertHeld();
        const unexpectedWal=root+'/local-models/registry.sqlite3-wal', walBytes=Buffer.from('unexpected original WAL must not be opened or removed');
        function refuseWal(){
          let candidate;
          try {
            assert.throws(()=>{candidate=new DatabaseSync(uri,{allowExtension:false});candidate.prepare('SELECT head FROM model_registry').get()},e=>e.code==='ERR_SQLITE_ERROR'&&e.errcode===3338);
          } finally {if(candidate)candidate.close()}
          store.assertHeld();
        }
        fs.writeFileSync(unexpectedWal,walBytes,{mode:0o600});
        const walBefore=fs.lstatSync(unexpectedWal,{bigint:true});refuseWal();
        const walAfter=fs.lstatSync(unexpectedWal,{bigint:true});
        for(const key of ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'])assert.equal(walAfter[key],walBefore[key]);
        assert.deepEqual(fs.readFileSync(unexpectedWal),walBytes);fs.unlinkSync(unexpectedWal);
        fs.symlinkSync(root+'/local-models/registry.sqlite3',unexpectedWal);refuseWal();
        assert.equal(fs.lstatSync(unexpectedWal).isSymbolicLink(),true);fs.unlinkSync(unexpectedWal);
        db=new DatabaseSync(uri,{allowExtension:false});assert.equal(db.prepare('SELECT head FROM model_registry').get().head,'head-1');
        assert.throws(()=>db.prepare('PRAGMA journal_mode=WAL').get(),e=>e.code==='ERR_SQLITE_ERROR');
        assert.equal(db.prepare('PRAGMA journal_mode').get().journal_mode,'delete');
        assert.equal(db.prepare('PRAGMA mmap_size=1048576').get().mmap_size,0);
        assert.equal(fs.existsSync(unexpectedWal),false);db.close();
        const small=Buffer.from('original immutable metadata'),smallRef=digest(small);
        store.publishSmallObject(smallRef,small);store.publishSmallObject(smallRef,small);
        assert.deepEqual(store.readSmallObject(smallRef),small);
        assert.equal(fs.statSync(root+'/local-models/objects/'+smallRef).mode&0o777,0o400);
        assert.throws(()=>store.publishSmallObject(smallRef,Buffer.from('different')),/differ/);
        const weights=Buffer.alloc(2*1024*1024+3,0x5a), tokenizer=Buffer.from('test tokenizer bytes'),signature=Buffer.alloc(64,0x37);
        const objects=[weights,tokenizer,signature].map(bytes=>({bytes,ref:digest(bytes)}));
        let sawWriter=false,sawReadonly=false;
        function objectAccessModes(file){
          const wanted=fs.statSync(file,{bigint:true}),modes=[];
          for(const name of fs.readdirSync('/proc/self/fd')){
            try {
              const held=fs.fstatSync(Number(name),{bigint:true});if(held.dev!==wanted.dev||held.ino!==wanted.ino)continue;
              const flags=fs.readFileSync('/proc/self/fdinfo/'+name,'utf8').split(String.fromCharCode(10)).find(line=>line.startsWith('flags:'));
              assert.ok(flags);const octal=flags.slice(6).trim();assert.match(octal,/^[0-7]+$/);modes.push(Number.parseInt(octal,8)&3);
            } catch(error){if(error.code!=='EBADF')throw error}
          }
          return modes;
        }
        function inspectTemporaryAccess(){
          for(const name of fs.readdirSync(root+'/local-models/objects').filter(name=>name.startsWith('.model-object-v1-'))){
            const file=root+'/local-models/objects/'+name,mode=fs.statSync(file).mode&0o777,access=objectAccessModes(file);
            if(mode===0o400){assert.deepEqual(access,[0]);sawReadonly=true}
            else{assert.equal(mode,0o600);assert.deepEqual(access,[2]);sawWriter=true}
          }
        }
        function makePackage(name){
          const dir=path.join(root,name);fs.mkdirSync(dir,{mode:0o700});fs.mkdirSync(dir+'/objects',{mode:0o700});
          fs.writeFileSync(dir+'/model-manifest.json','{}',{mode:0o600});
          for(const object of objects)fs.writeFileSync(dir+'/objects/'+object.ref,object.bytes,{mode:0o600});
          return dir;
        }
        function inventory(){const bytes=Buffer.alloc(objects.length*72);objects.forEach((object,i)=>{bytes.write(object.ref,i*72,64,'ascii');bytes.writeBigUInt64LE(BigInt(object.bytes.length),i*72+64)});return bytes}
        const packageRoot=makePackage('source');
        let original=store.openPackage(packageRoot+'/model-manifest.json');
        assert.deepEqual(original.readManifest(),Buffer.from('{}'));
        assert.throws(()=>store.openPackage(packageRoot+'/model-manifest.json'),/already/);
        const observed=original.captureInventory(inventory()); assert.equal(observed.length,objects.length*72);
        assert.deepEqual(original.readSignature(objects[2].ref),signature);
        assert.equal(original.copyObjectStep(objects[0].ref),false);inspectTemporaryAccess();
        assert.throws(()=>original.finish(),/incomplete/);
        original.close();original.close();
        assert.equal(fs.readdirSync(root+'/local-models/objects').some(name=>name.startsWith('.model-object-')),false);
        assert.equal(fs.existsSync(root+'/local-models/objects/'+objects[0].ref),false);
        original=store.openPackage(packageRoot+'/model-manifest.json');original.captureInventory(inventory());
        let steps=0;
        for(const object of objects){while(!original.copyObjectStep(object.ref)){inspectTemporaryAccess();assert.ok(++steps<10000);await new Promise(resolve=>setImmediate(resolve))}}
        original.finish();assert.ok(steps>32*3);assert.equal(sawWriter,true);assert.equal(sawReadonly,true);original.close();
        for(const object of objects){assert.equal(digest(fs.readFileSync(root+'/local-models/objects/'+object.ref)),object.ref);assert.equal(fs.statSync(root+'/local-models/objects/'+object.ref).mode&0o777,0o400)}
        original=store.openPackage(packageRoot+'/model-manifest.json');original.captureInventory(inventory());
        for(const object of objects)while(!original.copyObjectStep(object.ref))await new Promise(resolve=>setImmediate(resolve));
        original.finish();original.close();
        const extraRoot=makePackage('extra');fs.writeFileSync(extraRoot+'/objects/'+'1'.repeat(64),'extra',{mode:0o600});
        original=store.openPackage(extraRoot+'/model-manifest.json');assert.throws(()=>original.captureInventory(inventory()),/all and only/);original.close();
        const linkedRoot=makePackage('linked');fs.linkSync(linkedRoot+'/objects/'+objects[0].ref,root+'/elsewhere');
        original=store.openPackage(linkedRoot+'/model-manifest.json');assert.throws(()=>original.captureInventory(inventory()),/all and only/);original.close();
        const symlinkRoot=makePackage('symlink');fs.unlinkSync(symlinkRoot+'/objects/'+objects[0].ref);fs.symlinkSync(packageRoot+'/objects/'+objects[0].ref,symlinkRoot+'/objects/'+objects[0].ref);
        original=store.openPackage(symlinkRoot+'/model-manifest.json');assert.throws(()=>original.captureInventory(inventory()),/all and only/);original.close();
        const driftRoot=makePackage('drift');original=store.openPackage(driftRoot+'/model-manifest.json');original.captureInventory(inventory());
        assert.equal(original.copyObjectStep(objects[0].ref),false);
        fs.writeFileSync(driftRoot+'/objects/'+objects[0].ref,Buffer.alloc(weights.length,0x2a));
        assert.throws(()=>original.copyObjectStep(objects[0].ref),/integrity|custody/);original.close();
        store.assertHeld();store.close();store.close();assert.throws(()=>store.assertHeld(),/holder/);
        assert.throws(()=>native.deriveLocalModelStoreGate({}),/genuine/);
        const archiveGate=native.acquireKernelGlobalExclusive(), owner=native.acquireLock(root,true);
        const originalGate=native.bindMigrationCredentialGate(owner,archiveGate), modelGate=native.deriveLocalModelStoreGate(originalGate);
        assert.throws(()=>native.acquireLocalModelStore(fd,root,tuple,originalGate),/refused/);
        const archiveSource=native.acquireLocalModelStore(fd,root,tuple,modelGate);archiveSource.assertHeld();
        assert.deepEqual(archiveSource.readSmallObject(smallRef),small);
        assert.throws(()=>modelGate.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
        assert.throws(()=>originalGate.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
        assert.throws(()=>archiveSource.publishSmallObject(smallRef,small),/cannot publish/);
        assert.throws(()=>archiveSource.openPackage(packageRoot+'/model-manifest.json'),/cannot enroll/);
        assert.throws(()=>native.acquireCredentialScope(fd,root,tuple,modelGate),/gate|scope/);
        archiveSource.close();modelGate.close();originalGate.close();owner.close();
        const absentRoot=root+'-absent';fs.mkdirSync(absentRoot,{mode:0o700});
        const absentFd=fs.openSync(absentRoot,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
        const absentIdentity=fs.fstatSync(absentFd,{bigint:true}), absentTuple=[absentIdentity.dev,absentIdentity.ino,absentIdentity.uid,absentIdentity.gid,absentIdentity.mode];
        const absentOwner=native.acquireLock(absentRoot,true),absentOriginal=native.bindMigrationCredentialGate(absentOwner,archiveGate);
        const absentModelGate=native.deriveLocalModelStoreGate(absentOriginal);
        assert.equal(native.acquireLocalModelStore(absentFd,absentRoot,absentTuple,absentModelGate),null);
        assert.equal(fs.existsSync(absentRoot+'/local-models'),false);
        absentModelGate.close();absentOriginal.close();absentOwner.close();fs.closeSync(absentFd);archiveGate.close();
        const next=native.acquireLocalModelStore(fd,root,tuple);next.assertHeld();
        db=new DatabaseSync(uri,{allowExtension:false});db.exec('PRAGMA locking_mode=EXCLUSIVE;PRAGMA journal_mode=DELETE');
        assert.equal(db.prepare('SELECT head FROM model_registry').get().head,'head-1');db.close();next.close();fs.closeSync(fd);
        console.log('CLIQ_LOCAL_MODEL_STORE_ORIGINAL_FD_VERIFIED');
      })().catch(error=>{console.error(error);process.exitCode=1});
    `], { encoding: 'utf8', timeout: 90000, maxBuffer: 262144 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.match(child.stdout, /CLIQ_LOCAL_MODEL_STORE_ORIGINAL_FD_VERIFIED/u);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
