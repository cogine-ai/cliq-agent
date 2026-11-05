// Real disposable-account native component campaign of this complete package.
// These physical OS-lock/source/SQLite fixtures are not SQL StateOwner, Run,
// installation, migration completion or rollback authority evidence. No skip,
// synthetic process pause, lease extension or timeout-to-success is used.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, lstat, mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

async function writableOwnedDirectories(directory: string, uid: number): Promise<void> {
  const info = await lstat(directory); if (!info.isDirectory()) return;
  assert.equal(info.uid, uid); await chmod(directory, (info.mode & 0o7777) | 0o700);
  for (const entry of await readdir(directory)) await writableOwnedDirectories(path.join(directory, entry), uid);
}

test('canonical Legacy locks and original-driver archive retain and really join their original Linux resources',
  { timeout: 180000 }, async () => {
    assert.equal(process.platform, 'linux'); assert.equal(process.env.CLIQ_DISPOSABLE_ACCOUNT_QUALIFICATION, '1');
    const user = os.userInfo(); assert.equal(user.username, 'cliq-kernel-gate-test');
    assert.equal(user.homedir, '/home/cliq-kernel-gate-test'); assert.ok(user.uid >= 1000); assert.equal(process.geteuid?.(), user.uid);
    const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-migration-cohort-'));
    let failed = false, failure: unknown;
    try {
      const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
      const helper = path.join(fixture, 'state-owner.node');
      const source = fileURLToPath(new URL('../../../native/state-owner/state-owner.c', import.meta.url));
      const compile = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
        '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), source, '-o', helper],
      { encoding: 'utf8', timeout: 60000 });
      assert.equal(compile.error, undefined); assert.equal(compile.status, 0, compile.stderr); await chmod(helper, 0o500);
      const modules = Object.fromEntries(['native-owner', 'sqlite-driver'].map(name => [name,
        new URL(`../../../dist/state/${name}.js`, import.meta.url).href]));
      const canonical = new URL('../../../dist/kernel/canonical.js', import.meta.url).href;
      const identity = new URL('../../../dist/kernel/identity.js', import.meta.url).href;
      for (const mode of ['locks_normal', 'locks_existing_fresh', 'locks_existing_stale', 'locks_cancel_partial', 'archive', 'archive_empty']) {
        const root = path.join(fixture, mode);
        const child = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
          (async()=>{
            const assert=require('node:assert/strict'), fs=require('node:fs'), fsp=require('node:fs/promises'),
              crypto=require('node:crypto'), path=require('node:path'), {DatabaseSync,backup}=require('node:sqlite');
            const {canonicalJsonBytes,canonicalSha256}=await import(${JSON.stringify(canonical)});
            const {digestOmitting}=await import(${JSON.stringify(identity)});
            const root=${JSON.stringify(root)}, mode=${JSON.stringify(mode)}, helper=${JSON.stringify(helper)};
            fs.mkdirSync(root,{mode:0o700});process.chdir(root);
            const names=${JSON.stringify(modules)};
            if(mode==='archive'||mode==='archive_empty'){
              const api=await import(names['native-owner']), sql=await import(names['sqlite-driver']);
              const image=await fsp.open(helper,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
              const native=await api.loadHeldStateOwnerImage(image);
              const gate=api.acquireHeldKernelGlobalExclusive(native), owner=native.acquireLock(root,true);
              const bound=api.bindHeldMigrationCredentialGate(native,owner,gate), rootIdentity=api.stateRootIdentityForLock(owner);
              fs.mkdirSync(path.join(root,'migration'),{recursive:true,mode:0o700});
              const source=sql.openSqliteDriver(path.join(root,'kernel.sqlite3'));
              source.exec('PRAGMA synchronous=FULL;PRAGMA journal_mode=DELETE;CREATE TABLE proof(value TEXT NOT NULL) STRICT');
              source.transaction(c=>{const insert=c.prepare('INSERT INTO proof VALUES(?)');for(let i=0;i<512;i++)insert.run('source-'+i+'-'.repeat(4096));});
              const original=source.prepare('SELECT count(*) AS n FROM proof').get().n;
              let control;
              const make=async()=>{
                const data={schemaVersion:1,format:'cliq-kernel-rollback-control-v1',phase:'rollback_draining',controlRevision:1,
                  migrationId:crypto.randomBytes(32).toString('base64url'),archiveId:crypto.randomBytes(32).toString('base64url'),
                  kernelGenerationId:crypto.randomBytes(32).toString('base64url'),stateRootIdentityRef:canonicalSha256(rootIdentity),
                  stateRootIdentityDigest:rootIdentity.identityDigest,stateRootCanonicalAbsolutePath:root,
                  requestRef:crypto.createHash('sha256').update('component-request').digest('hex'),requestDigest:crypto.createHash('sha256').update('component-request').digest('hex'),
                  originalImportControlRef:crypto.createHash('sha256').update('component-import-control').digest('hex'),originalImportControlDigest:crypto.createHash('sha256').update('component-import-control-digest').digest('hex'),
                  originalKernelAuthorityRef:crypto.createHash('sha256').update('component-source-reference').digest('hex'),originalKernelAuthorityDigest:crypto.createHash('sha256').update('component-source-digest').digest('hex'),
                  preparedAt:new Date().toISOString(),controlDigest:''};
                data.controlDigest=digestOmitting(data,'controlDigest');control=data;
                fs.writeFileSync(path.join(root,'migration/control-v1.json'),canonicalJsonBytes(data),{mode:0o600});
                return api.createHeldKernelArchive(native,bound,image,data);
              };
              const casRoot=path.join(root,'cas');fs.mkdirSync(casRoot,{mode:0o700});
              const fixtureBytes=[Buffer.from('unreferenced-published-object'),Buffer.from('complete-ref-temporary'),Buffer.from('partial-stream-temporary')];
              const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
              const fixtureNames=[sha(fixtureBytes[0]),'.tmp-'+sha(fixtureBytes[1])+'-'+ 'c'.repeat(32),'.tmp-stream-'+ 'b'.repeat(32)];
              if(mode==='archive')for(let i=0;i<fixtureNames.length;i++){
                const file=path.join(casRoot,fixtureNames[i]);fs.writeFileSync(file,fixtureBytes[i],{mode:i===2?0o600:0o400});
                const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
              }
              const casDirectory=fs.openSync(casRoot,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
              try{fs.fsyncSync(casDirectory);}finally{fs.closeSync(casDirectory);}
              const sourceBefore=fs.readdirSync(casRoot).sort().map(name=>{const st=fs.lstatSync(path.join(casRoot,name),{bigint:true});return{name,dev:String(st.dev),ino:String(st.ino),size:String(st.size),mode:Number(st.mode&0o777n),sha256:sha(fs.readFileSync(path.join(casRoot,name)))};});
              // Exact fixed model-store absence, before any archive birth.
              const localStore=path.join(root,'local-models');fs.mkdirSync(localStore,{mode:0o700});
              await assert.rejects(make());assert.equal(fs.existsSync(path.join(root,'migration/kernel-archives')),false);
              assert.equal(fs.existsSync(path.join(root,'file:')),false);fs.rmdirSync(localStore);
              fs.symlinkSync('cas',localStore);await assert.rejects(make());
              assert.equal(fs.existsSync(path.join(root,'migration/kernel-archives')),false);fs.unlinkSync(localStore);
              const archive=await make(), birth=api.describeHeldKernelArchiveBirth(archive);
              assert.equal(birth.localModelStore,'absent');
              const operation=sql.backupOriginalSqliteToKernelArchive(source,archive);
              assert.throws(()=>source.close(),e=>e.code==='RESOURCE_RETIREMENT_REQUIRED'||e.name==='ResourceRetirementError');
              const joined=await operation;assert.equal(joined.outcome,'commit_phase_two_observed');
              assert.equal(joined.mainOpens,1);assert.equal(joined.mainCloses,1);assert.equal(joined.journalBirths,joined.journalDeletions);
              const sealed=await api.sealHeldKernelArchive(archive);assert.equal(sealed.mode,0o400);
              assert.deepEqual(sealed.file,birth.file);
              const locator=path.join(root,'migration/kernel-archives',control.archiveId,'kernel.sqlite3');
              const hash=crypto.createHash('sha256').update(fs.readFileSync(locator)).digest('hex');assert.equal(sealed.sha256,hash);
              const uri=api.beginHeldKernelArchiveRead(archive), read=new DatabaseSync(uri,{readOnly:true,allowExtension:false});
              assert.equal(read.prepare('SELECT count(*) AS n FROM proof').get().n,Number(original));
              assert.throws(()=>read.exec("INSERT INTO proof VALUES('forbidden')"));
              assert.throws(()=>new DatabaseSync(uri.replace(/cliq_archive_lease=[0-9a-f]+/,'cliq_archive_lease='+ '0'.repeat(64)),{readOnly:true}));
              read.close();api.endHeldKernelArchiveRead(archive);
              assert.deepEqual(await api.sealHeldKernelArchive(archive),sealed);
              const captured=await api.captureHeldKernelArchiveCas(archive,sealed.byteCount);
              const capturedEntries=[];for await(const page of captured.entries)capturedEntries.push(...page);
              assert.equal(captured.identity.layout,'cliq-flat-cas-v1');assert.equal(captured.identity.entryCount,sourceBefore.length);
              assert.equal(captured.identity.combinedPayloadBytes,sealed.byteCount+fixtureBytes.slice(0,mode==='archive'?3:0).reduce((sum,bytes)=>sum+bytes.length,0));
              assert.deepEqual(capturedEntries.map(entry=>entry.name),sourceBefore.map(entry=>entry.name));
              for(const entry of capturedEntries){
                const original=sourceBefore.find(source=>source.name===entry.name), target=path.join(root,'migration/kernel-archives',control.archiveId,'cas',entry.name);
                const st=fs.lstatSync(target,{bigint:true});assert.equal(entry.sha256,original.sha256);assert.equal(entry.byteCount,Number(original.size));
                assert.equal(entry.sourceFileId,original.ino);assert.equal(entry.archiveFileId,String(st.ino));assert.notEqual(entry.sourceFileId,entry.archiveFileId);
                assert.equal(st.nlink,1n);assert.equal(Number(st.mode&0o777n),0o400);assert.equal(sha(fs.readFileSync(target)),original.sha256);
                assert.equal(entry.sourceMode,original.mode);
              }
              // Component manifest bytes exercise real fixed native custody;
              // they do not pretend to be a completed rollback authority root.
              const manifestBytes=canonicalJsonBytes({format:'cliq-native-archive-component-v1',imageSha256:sealed.sha256,namespace:captured.identity,entries:capturedEntries});
              const manifest=await api.sealHeldKernelArchiveManifest(archive,manifestBytes);
              const manifestPath=path.join(root,'migration/kernel-archives',control.archiveId,'manifest-v1.json');
              assert.equal(manifest.sha256,sha(manifestBytes));assert.equal(manifest.byteCount,manifestBytes.length);
              assert.deepEqual(fs.readFileSync(manifestPath),manifestBytes);assert.equal(Number(fs.statSync(manifestPath).mode&0o777),0o400);
              await assert.rejects(api.sealHeldKernelArchiveManifest(archive,manifestBytes));
              assert.deepEqual(fs.readdirSync(casRoot).sort().map(name=>{const st=fs.lstatSync(path.join(casRoot,name),{bigint:true});return{name,dev:String(st.dev),ino:String(st.ino),size:String(st.size),mode:Number(st.mode&0o777n),sha256:sha(fs.readFileSync(path.join(casRoot,name)))};}),sourceBefore);
              archive.close();
              assert.equal(source.prepare('SELECT count(*) AS n FROM proof').get().n,original);
              const cancelled=await make(), abort=new AbortController();abort.abort(new Error('component cancellation before dispatch'));
              await assert.rejects(sql.backupOriginalSqliteToKernelArchive(source,cancelled,abort.signal),/component cancellation/);
              cancelled.close();
              const active=await make(), stop=new AbortController(), diagnostic=require('node:diagnostics_channel');
              const progress=diagnostic.channel(sql.KERNEL_ARCHIVE_PROGRESS_CHANNEL);let entered=false,observerFailure;
              const observer=info=>{try{
                if(!entered&&info.phase==='sqlite_step'&&info.totalPages>info.remainingPages&&info.remainingPages>0){
                  entered=true;stop.abort(new Error('component cancellation after actual SQLite step'));
                }
              }catch(error){observerFailure=error;}};
              progress.subscribe(observer);
              let cancelledError;
              try { await assert.rejects(sql.backupOriginalSqliteToKernelArchive(source,active,stop.signal).catch(error=>{cancelledError=error;throw error;}),/component cancellation after actual SQLite step/); }
              finally { progress.unsubscribe(observer); }
              assert.equal(observerFailure,undefined);assert.equal(entered,true,'in-flight evidence requires actual nonfinal SQLite page progress');
              assert(cancelledError instanceof AggregateError,'cancel classification requires the actual cancelled native join');
              assert.equal(cancelledError.errors.length,2);assert.equal(cancelledError.errors[0],stop.signal.reason);
              assert(cancelledError.errors[1] instanceof Error,'original SQLite rejection must remain available for audit');
              assert.equal(cancelledError.cause,stop.signal.reason);
              assert.throws(()=>api.beginHeldKernelArchiveRead(active));active.close();
              assert.equal(source.prepare('SELECT count(*) AS n FROM proof').get().n,original);
              source.close();bound.close();owner.close();gate.close();await image.close();return;
            }
            const loaded={exports:{}};process.dlopen(loaded,helper);const native=loaded.exports;
            const legacy=root+'-legacy';fs.mkdirSync(legacy,{mode:0o700});
            for(const rel of ['sessions/2026/01/02','plans/workspace/session/plan','tx/tx_valid','foreign.lock'])fs.mkdirSync(path.join(legacy,rel),{recursive:true,mode:0o700});
            const sourcePath='sessions/2026/01/02/source.json';
            fs.writeFileSync(path.join(legacy,sourcePath),JSON.stringify({version:5,app:'cliq',id:'source',cwd:'/old/source',createdAt:'2026-01-01T00:00:00.000Z',updatedAt:'2026-01-02T00:00:00.000Z',model:{},lifecycle:{status:'idle',turn:0},records:[],checkpoints:[],compactions:[]}),{mode:0o600});
            for(const rel of ['plans/workspace/session/plan/plan.json','plans/workspace/session/plan/progress.json','tx/tx_valid/state.json','foreign.lock/data.txt'])fs.writeFileSync(path.join(legacy,rel),'component-data',{mode:0o600});
            const existing=path.join(legacy,sourcePath+'.lock');
            if(mode.startsWith('locks_existing')){
              fs.mkdirSync(existing,{mode:0o700});fs.writeFileSync(path.join(existing,'owner'),'999999:foreign-fixture',{mode:0o600});
              if(mode==='locks_existing_stale'){const old=new Date(Date.now()-60000);fs.utimesSync(path.join(existing,'owner'),old,old);}
            }
            const gate=native.acquireKernelGlobalExclusive(), owner=native.acquireLock(root,true), bound=native.bindMigrationCredentialGate(owner,gate);
            const migrationId=crypto.randomBytes(32).toString('base64url'), scope=native.acquireMigrationFilesystem(bound,migrationId,legacy);
            fs.mkdirSync(path.join(root,'cas'),{recursive:true,mode:0o700});
            // Actual component bytes and native durable publication; this is
            // not a SQL Owner/preparation or a completed migration receipt.
            const preparation=canonicalJsonBytes({format:'cliq-native-component-preparation-v1',migrationId}), ref=crypto.createHash('sha256').update(preparation).digest('hex');
            fs.writeFileSync(path.join(root,'cas',ref),preparation,{mode:0o400});
            const rootData=(await import(names['native-owner'])).stateRootIdentityFromDescriptor(root,owner.root);
            const controlData={schemaVersion:1,format:'cliq-migration-control-v1',phase:'cutover_preflight',controlRevision:1,
              migrationId,sourceGenerationDigest:canonicalSha256(scope.observeRoots().legacyRoot),targetGenerationId:crypto.randomBytes(32).toString('base64url'),
              stateRootIdentityRef:canonicalSha256(rootData),stateRootIdentityDigest:rootData.identityDigest,stateRootCanonicalAbsolutePath:root,
              preparationRef:ref,preparationDigest:ref,createdAt:new Date().toISOString(),updatedAt:'',controlDigest:''};
            controlData.updatedAt=controlData.createdAt;controlData.controlDigest=digestOmitting(controlData,'controlDigest');
            const closed=await import(${JSON.stringify(new URL('../../../dist/kernel/migration-control.js', import.meta.url).href)});
            scope.publishInitialSpine(ref,canonicalJsonBytes(closed.decodeOwnedLegacyImportControl(controlData)));
            const lockDirs=['auth.json.lock','workspace-state.lock',sourcePath+'.lock','plans/workspace/session/plan/plan.json.lock','plans/workspace/session/plan/progress.json.lock','tx/tx_valid/tx.lock'];
            if(mode.startsWith('locks_existing')){
              assert.throws(()=>{for(let i=0;i<10000;i++)if(scope.prepareLegacyLocksNext())throw new Error('unexpected complete');},error=>error.code==='ERR_CLIQ_MIGRATION_FILESYSTEM');
              await scope.releaseLegacyLocks();scope.close();assert.equal(fs.readFileSync(path.join(existing,'owner'),'utf8'),'999999:foreign-fixture');
            }else if(mode==='locks_cancel_partial'){
              let partial=false;for(let i=0;i<10000;i++){const complete=scope.prepareLegacyLocksNext();if(fs.existsSync(path.join(legacy,'auth.json.lock'))){assert.equal(complete,false);partial=true;break;}}
              assert(partial);await scope.releaseLegacyLocks();scope.close();for(const rel of lockDirs)assert.equal(fs.existsSync(path.join(legacy,rel)),false);
            }else{
              let complete=false;for(let i=0;i<10000;i++)if(scope.prepareLegacyLocksNext()){complete=true;break;}assert(complete);scope.assertLegacyLocks();
              const token=path.join(legacy,'auth.json.lock/owner'), first=fs.statSync(token,{bigint:true}).mtimeNs;
              const work=new DatabaseSync(path.join(root,'kernel.sqlite3'));work.exec('PRAGMA synchronous=FULL;PRAGMA journal_mode=DELETE;CREATE TABLE work(value TEXT) STRICT');
              const insert=work.prepare('INSERT INTO work VALUES(?)'), start=process.hrtime.bigint();let writes=0;
              // Normal real SQLite FULL commits occupy JS while the actual
              // native thread renews. No timer, busyloop or process pause.
              while(process.hrtime.bigint()-start<2100000000n&&writes<10000){insert.run('real-work-'+writes+'-'.repeat(2048));writes++;}
              assert(process.hrtime.bigint()-start>=2100000000n);assert(writes>0);work.close();
              scope.assertLegacyLocks();assert(fs.statSync(token,{bigint:true}).mtimeNs>first);
              assert.equal(scope.observeOriginalAuth().presence,'absent');
              const own=new Set(lockDirs.map(rel=>{const s=fs.statSync(path.join(legacy,rel),{bigint:true});return s.dev+':'+s.ino;}));
              const entries=[];for(;;){const entry=scope.copyBackupNext();if(entry===null)break;if(entry!==false)entries.push(entry);}
              assert(entries.some(e=>e.canonicalRootRelativePath==='foreign.lock/data.txt'));
              for(const entry of entries)assert(!own.has(entry.sourceIdentity.deviceId+':'+entry.sourceIdentity.fileId));
              fs.writeFileSync(path.join(legacy,'sessions/2026/01/02/new.json'),'uncooperative-test-fixture',{mode:0o600});
              assert.throws(()=>scope.assertLegacyLocks(),/Legacy|lock|cohort/);
              await scope.releaseLegacyLocks();scope.close();for(const rel of lockDirs)assert.equal(fs.existsSync(path.join(legacy,rel)),false);
              assert.equal(fs.readFileSync(path.join(legacy,'foreign.lock/data.txt'),'utf8'),'component-data');
              // New current-reader role after the old creator and its original
              // locks have actually closed. Component marker bytes are inert;
              // this is not a SQL migration/rollback or credential authority.
              fs.unlinkSync(path.join(legacy,'sessions/2026/01/02/new.json'));
              const marker=canonicalJsonBytes({format:'cliq-native-inspector-component-v1',migrationId,purpose:'readonly_component'});
              const auth=canonicalJsonBytes({format:'cliq-native-inspector-auth-component-v1',migrationId,purpose:'nonsecret_component'});
              for(const [file,bytes] of [[path.join(root,'migration/authority-v1.json'),marker],[path.join(legacy,'.cliq-generation-v1.json'),marker],[path.join(legacy,'auth.json'),auth]]){
                fs.writeFileSync(file,bytes,{mode:0o600});const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
                try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
              }
              const backupRoot=path.join(root,'migration/owned-import',migrationId,'backup');
              // Current source proof owns no old temporary candidate/archive.
              // Both are genuinely empty here and the old creator has closed.
              fs.rmdirSync(path.join(root,'migration/owned-import',migrationId,'candidate'));
              fs.rmdirSync(path.join(root,'migration/owned-import',migrationId,'archive'));
              const originalSourceRoot=fs.lstatSync(legacy,{bigint:true}), originalBackupRoot=fs.lstatSync(backupRoot,{bigint:true});
              const roots=[originalSourceRoot.dev,originalSourceRoot.ino,originalSourceRoot.mode&0o7777n,
                originalBackupRoot.dev,originalBackupRoot.ino,originalBackupRoot.mode&0o7777n,BigInt(process.geteuid()),BigInt(entries.length)];
              // One real original-holder online copy/namespace/seal. These
              // component bytes establish no SQL history or rollback authority.
              const archiveId=crypto.randomBytes(32).toString('base64url');
              const physicalArchive=native.createKernelArchive(bound,migrationId,archiveId,fs.readFileSync(path.join(root,'migration/control-v1.json')));
              const originalDatabase=new DatabaseSync(path.join(root,'kernel.sqlite3')), archiveUri=physicalArchive.beginBackup();
              const bootstrap=new DatabaseSync(':memory:',{allowExtension:true});
              try{bootstrap.loadExtension(helper,'sqlite3_cliqownedarchive_init');bootstrap.enableLoadExtension(false);}finally{bootstrap.close();}
              await backup(originalDatabase,archiveUri,{rate:64});
              assert.equal(physicalArchive.joinBackup().outcome,'commit_phase_two_observed');
              let imageSealed=false;for(let i=0;i<10000;i++)if(physicalArchive.sealNext()){imageSealed=true;break;}assert(imageSealed);
              const physicalImage=physicalArchive.identity(), physicalBirth=physicalArchive.describeBirth();
              physicalArchive.beginCasCapture();let casComplete=false;for(let i=0;i<10000;i++)if(physicalArchive.captureCasNext()){casComplete=true;break;}assert(casComplete);
              const physicalCas=physicalArchive.casCaptureIdentity(), physicalEntries=[];
              for(let start=0;start<physicalCas.entryCount;start+=64)physicalEntries.push(...physicalArchive.readCasCaptureEntries(start));
              const physicalManifestBytes=canonicalJsonBytes({format:'cliq-current-archive-native-component-v1',physicalImage,physicalCas,physicalEntries});
              physicalArchive.beginManifest(physicalManifestBytes);let manifestSealed=false;
              for(let i=0;i<10000;i++)if(physicalArchive.sealManifestNext()){manifestSealed=true;break;}assert(manifestSealed);
              const physicalManifest=physicalArchive.manifestIdentity();physicalArchive.close();originalDatabase.close();
              const openCurrent=()=>native.openCurrentMigrationInspector(bound,migrationId,archiveId,legacy,roots,
                fs.readFileSync(path.join(root,'migration/control-v1.json')),marker,marker,auth);
              const current=openCurrent();
              const originalCallbacks=['assertHeld','close','prepareLegacyLocksNext','assertLegacyLocks','releaseLegacyLocks','observeRoots',
                'publishInitialSpine','advanceControl','observeOriginalAuth','publishAuthCutover','publishKernelAuthority','readControlBytes',
                'readPreparationBytes','readRendezvousBytes','assertCredentialCutoverControl','readBackupInventoryPage','createCandidate',
                'candidateBuildPath','sealCandidateNext','copyBackupNext','verifyBackupSourceNext','beginContextProjection',
                'nextContextSource','readContextSourceChunk','closeContextSource'];
              for(const name of originalCallbacks)
                assert.throws(()=>scope[name].call(current),/receiver/,'old creator callback must reject the new native tag first');
              let currentLocked=false;for(let i=0;i<10000;i++)if(current.prepareLegacyLocksNext()){currentLocked=true;break;}
              assert(currentLocked);current.assertLegacyLocks();
              const packet=await import(${JSON.stringify(new URL('../../../dist/kernel/current-migration-inspection-data.js', import.meta.url).href)});
              entries.sort((a,b)=>Buffer.compare(Buffer.from(a.canonicalRootRelativePath),Buffer.from(b.canonicalRootRelativePath)));
              for(const entry of entries){current.beginExpectedEntry(packet.encodeCurrentMigrationExpectedEntry(entry));
                let verified=false;for(let i=0;i<10000;i++)if(current.verifyExpectedEntryNext()){verified=true;break;}assert(verified);}
              current.finishExpectedEntries();current.beginWholeTreeVerification();
              let trees=false;for(let i=0;i<10000;i++)if(current.verifyWholeTreesNext()){trees=true;break;}assert(trees);
              const observed=current.inspectRetainedLegacy();assert.equal(observed.kind,'retained_original_objects_unchanged');
              assert.equal(observed.sourceAuth,'matched_original_marker');assert.equal(observed.entryCount,entries.length);
              assert.equal(observed.byteCount,entries.reduce((sum,entry)=>sum+(entry.kind==='regular_file'?entry.byteCount:0),0));
              const archivePackets=await import(${JSON.stringify(new URL('../../../dist/kernel/current-kernel-archive-data.js', import.meta.url).href)});
              const selection={archiveCollection:physicalBirth.archiveCollection,archiveDirectory:physicalBirth.archiveDirectory,manifest:physicalManifest};
              const payload=Buffer.alloc(160);payload.write('CLQMH001');const pair=(at,id)=>{payload.writeBigUInt64LE(BigInt(id.deviceId),at);payload.writeBigUInt64LE(BigInt(id.fileId),at+8);};
              pair(8,physicalImage.file);payload.writeBigUInt64LE(BigInt(physicalImage.byteCount),24);Buffer.from(physicalImage.sha256,'hex').copy(payload,32);
              pair(64,physicalCas.sourceDirectory);pair(80,physicalCas.archiveDirectory);payload.writeBigUInt64LE(BigInt(physicalCas.entryCount),96);
              payload.writeBigUInt64LE(BigInt(physicalCas.totalBytes),104);payload.writeBigUInt64LE(BigInt(physicalCas.combinedPayloadBytes),112);
              payload.writeUInt32LE(process.geteuid(),120);Buffer.from(physicalCas.entriesDigest,'hex').copy(payload,128);
              const step=(operation)=>{let complete=false;for(let i=0;i<10000;i++)if(operation()){complete=true;break;}assert(complete);};
              const openArchive=(reader)=>{
                reader.selectOriginalKernelArchive(archivePackets.encodeCurrentArchiveManifestSelection(selection));
                step(()=>reader.verifyArchiveManifestNext());const chunks=[];
                for(;;){const next=reader.readArchiveManifestChunk();if(next===null)break;assert(next.length<=65536);chunks.push(next);}
                assert.deepEqual(Buffer.concat(chunks),physicalManifestBytes);
                reader.selectArchivePayload(payload);step(()=>reader.verifyArchiveImageNext());reader.beginArchiveEntryPass();
                // Native byte/identity coverage only. Production independently
                // validates its full strict header and both bounded streams.
                let supplied=false;for(;;){const next=reader.readArchiveManifestChunk();if(next===null)break;
                  if(!supplied){supplied=true;for(const entry of physicalEntries){
                    reader.beginArchiveCasEntry(archivePackets.encodeCurrentArchiveCasEntry(entry));step(()=>reader.verifyArchiveCasEntryNext());}}}
              };
              openArchive(current);step(()=>current.verifyArchiveNamespaceNext());
              const archiveObserved=current.inspectVerifiedArchive();assert.equal(archiveObserved.kind,'current_checked_original_archive');
              assert.equal(archiveObserved.entryCount,physicalCas.entryCount);assert.equal(archiveObserved.manifestSha256,physicalManifest.sha256);
              assert.equal(archiveObserved.totalBytes,physicalCas.combinedPayloadBytes+physicalManifest.byteCount);
              assert.deepEqual(archiveObserved.databaseFile,physicalImage.file);assert.deepEqual(archiveObserved.casDirectory,physicalCas.archiveDirectory);
              fs.writeFileSync(path.join(legacy,'current-unexpected.txt'),'uncooperative-current-fixture',{mode:0o600});
              assert.throws(()=>{current.beginWholeTreeVerification();for(let i=0;i<10000;i++)if(current.verifyWholeTreesNext())throw new Error('unexpected complete');},error=>error.code==='ERR_CLIQ_MIGRATION_FILESYSTEM');
              await current.releaseLegacyLocks();current.close();
              for(const rel of lockDirs)assert.equal(fs.existsSync(path.join(legacy,rel)),false);
              fs.unlinkSync(path.join(legacy,'current-unexpected.txt'));
              // Data refusal cannot manufacture failed FD retirement. The
              // original receiver still joins/consumes its actual resources.
              assert(physicalEntries.length>0);const damaged=physicalEntries[0], damagedPath=path.join(root,'migration/kernel-archives',archiveId,'cas',damaged.name);
              fs.chmodSync(damagedPath,0o600);const oldBytes=fs.readFileSync(damagedPath);fs.writeFileSync(damagedPath,Buffer.alloc(oldBytes.length,0x78));fs.chmodSync(damagedPath,0o400);
              const damagedReader=openCurrent();step(()=>damagedReader.prepareLegacyLocksNext());
              assert.throws(()=>openArchive(damagedReader),error=>error.code==='ERR_CLIQ_MIGRATION_FILESYSTEM');
              await damagedReader.releaseLegacyLocks();damagedReader.close();bound.assertHeld();
              fs.chmodSync(damagedPath,0o600);fs.writeFileSync(damagedPath,oldBytes);fs.chmodSync(damagedPath,0o400);
              const extraPath=path.join(root,'migration/kernel-archives',archiveId,'cas','unregistered-extra');fs.writeFileSync(extraPath,'must not be omitted',{mode:0o400});
              const extraReader=openCurrent();step(()=>extraReader.prepareLegacyLocksNext());openArchive(extraReader);
              assert.throws(()=>step(()=>extraReader.verifyArchiveNamespaceNext()),error=>error.code==='ERR_CLIQ_MIGRATION_FILESYSTEM');
              await extraReader.releaseLegacyLocks();extraReader.close();bound.assertHeld();fs.unlinkSync(extraPath);
              fs.mkdirSync(existing,{mode:0o700});fs.writeFileSync(path.join(existing,'owner'),'999999:current-foreign',{mode:0o600});
              const oldCurrent=new Date(Date.now()-60000);fs.utimesSync(path.join(existing,'owner'),oldCurrent,oldCurrent);
              const refused=openCurrent();assert.throws(()=>{for(let i=0;i<10000;i++)if(refused.prepareLegacyLocksNext())throw new Error('unexpected complete');},error=>error.code==='ERR_CLIQ_MIGRATION_FILESYSTEM');
              await refused.releaseLegacyLocks();refused.close();assert.equal(fs.readFileSync(path.join(existing,'owner'),'utf8'),'999999:current-foreign');
              console.log(JSON.stringify({diagnosticOnly:true,scope:'native-current-inspector-component',entries:observed.entryCount,
                oldReceiverRefusals:originalCallbacks.length,fullSourceAndBackup:true,unexpectedEntryRefused:true,foreignStaleLockPreserved:true,
                originalOnlineArchive:true,fullArchiveImageAndNamespace:true,changedArchiveBytesRefused:true,extraArchiveObjectRefused:true,
                originalResourcesJoinedAfterDataRefusal:true}));

            }
            bound.close();owner.close();gate.close();
          })().catch(error=>{console.error(error);process.exitCode=1;});
        `], { encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
        assert.equal(child.error, undefined, mode); assert.equal(child.signal, null, `${mode}: ${child.stderr}`);
        assert.equal(child.status, 0, `${mode}: ${child.stderr}`);
        if (mode === 'locks_normal') console.log(child.stdout.trim());
      }
    } catch (error) { failed = true; failure = error; }
    try { await writableOwnedDirectories(fixture, user.uid); await rm(fixture, { recursive: true, force: true }); }
    catch (error) { if (failed) throw new AggregateError([failure, error], 'native cohort and test-owned cleanup failed', { cause: failure }); throw error; }
    if (failed) throw failure;
  });
