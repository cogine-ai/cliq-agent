// Real original StateOwner OS lock/account EX/native fixed scope/read FD/Node
// SQLite mechanism campaign. No synthetic SQL StateOwner, Run, death, install,
// migration control or creator receipt is constructed. Not complete I4 proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, lstat, mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

/** Test-owned fixture teardown only, after every real child has joined. Do not
 * follow links or chmod files/foreign directories; native sealed data remains
 * readonly for the complete mechanism assertions above this cleanup. */
async function writableOwnedFixtureDirectories(directory: string, uid: number): Promise<void> {
  const info = await lstat(directory);
  if (!info.isDirectory()) return;
  assert.equal(info.uid, uid, 'fixture cleanup cannot change a foreign directory');
  await chmod(directory, (info.mode & 0o7777) | 0o700);
  for (const entry of await readdir(directory)) await writableOwnedFixtureDirectories(path.join(directory, entry), uid);
}

test('sealed original-FD candidate lease, full rereads and fixed SQLite policy on an actual disposable Linux account',
  { timeout: 180000 }, async () => {
    assert.equal(process.platform, 'linux');
    assert.equal(process.env.CLIQ_DISPOSABLE_ACCOUNT_QUALIFICATION, '1', 'missing real disposable-account fixture is a failure, never skipped proof');
    const user = os.userInfo();
    assert.equal(user.username, 'cliq-kernel-gate-test'); assert.equal(user.homedir, '/home/cliq-kernel-gate-test');
    assert.ok(user.uid >= 1000); assert.equal(process.geteuid?.(), user.uid);
    const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-prepared-preview-'));
    let caseFailed = false, caseFailure: unknown;
    try {
      const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
      const helper = path.join(fixture, 'state-owner.node');
      const source = fileURLToPath(new URL('../../../native/state-owner/state-owner.c', import.meta.url));
      const policy = new URL('../../../dist/state/prepared-import-candidate.js', import.meta.url).href;
      const compile = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
        '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), source, '-o', helper],
      { encoding: 'utf8', timeout: 60000 });
      assert.equal(compile.error, undefined); assert.equal(compile.status, 0, compile.stderr);
      for (const mode of ['normal', 'sidecar', 'hardlink', 'replacement', 'changed_bytes']) {
        const root = path.join(fixture, mode);
        const result = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
          (async()=>{
            const assert=require('node:assert/strict'), fs=require('node:fs'), crypto=require('node:crypto'), path=require('node:path');
            const {DatabaseSync}=require('node:sqlite');
            const loaded={exports:{}};process.dlopen(loaded,${JSON.stringify(helper)});const native=loaded.exports;
            const root=${JSON.stringify(root)}, legacy=root+'-legacy', mode=${JSON.stringify(mode)};fs.mkdirSync(root,{mode:0o700});fs.mkdirSync(legacy,{mode:0o700});
            let sourceBytes;
            if(mode==='normal') {
              fs.mkdirSync(path.join(legacy,'sessions/2026/01/02'),{recursive:true,mode:0o700});
              sourceBytes=Buffer.from(JSON.stringify({version:5,app:'cliq',id:'source',cwd:'/old/source',
                createdAt:'2026-01-01T00:00:00.000Z',updatedAt:'2026-01-02T00:00:00.000Z',model:{},
                lifecycle:{status:'idle',turn:0},records:[{id:'record',ts:'2026-01-01T00:00:00.000Z',
                  kind:'user',role:'user',content:'real-source-'.repeat(12000)}],checkpoints:[],compactions:[]}));
              fs.writeFileSync(path.join(legacy,'sessions/2026/01/02/source.json'),sourceBytes,{mode:0o600,flag:'wx'});
            }
            const gate=native.acquireKernelGlobalExclusive(), owner=native.acquireLock(root,true);
            const bound=native.bindMigrationCredentialGate(owner,gate);
            const id=crypto.randomBytes(32).toString('base64url');
            const scope=native.acquireMigrationFilesystem(bound,id,legacy);
            assert.throws(()=>native.openPreparedImportCandidate({}),/original|filesystem/);
            assert.throws(()=>native.openPreparedImportCandidate(scope),/sealed|image/);
            assert.throws(()=>native.acquireMigrationFilesystem(bound,id,legacy),/creation|existing|custody/);
            scope.assertHeld();while(scope.copyBackupNext()!==null){}
            const readSource=()=>{
              const selected=scope.nextContextSource();assert(selected);assert.equal(selected.canonicalRootRelativePath,'sessions/2026/01/02/source.json');
              const parts=[];for(;;){const bytes=scope.readContextSourceChunk();if(bytes===null)break;assert(bytes.length<=65536);parts.push(bytes);}
              assert(parts.length>1);assert.deepEqual(Buffer.concat(parts),sourceBytes);scope.closeContextSource();
              assert.equal(scope.nextContextSource(),null);return selected;
            };
            const firstSource=mode==='normal'?readSource():undefined;
            if(mode!=='normal')assert.equal(scope.nextContextSource(),null);
            if(mode==='normal')while(!scope.verifyBackupSourceNext()){}
            scope.createCandidate();
            if(mode==='normal') {
              scope.beginContextProjection();const projected=readSource();
              assert.deepEqual(projected.sourceIdentity,firstSource.sourceIdentity);
              assert.equal(projected.contentDigest,firstSource.contentDigest);
              while(!scope.verifyBackupSourceNext()){}
            }
            const buildPath=scope.candidateBuildPath();
            assert.equal(buildPath,path.join(root,'migration/owned-import',id,'candidate/kernel.sqlite3'));
            const originalImage=fs.statSync(buildPath,{bigint:true});
            const sameImageFds=()=>fs.readdirSync('/proc/self/fd').filter(name=>{
              if(!/^[0-9]+$/.test(name))return false;
              try{const actual=fs.fstatSync(Number(name),{bigint:true});return actual.dev===originalImage.dev&&actual.ino===originalImage.ino;}
              catch(error){if(error.code==='EBADF'||error.code==='ENOENT')return false;throw error;}
            }).sort();
            const originalFds=sameImageFds();assert.equal(originalFds.length,1,'only the real parent owns the new image before SQLite opens');
            const writer=new DatabaseSync(buildPath,{enableForeignKeyConstraints:true,enableDoubleQuotedStringLiterals:false});
            writer.exec('PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; CREATE TABLE proof(value TEXT NOT NULL) STRICT');
            const content='complete-held-image-'.repeat(16000);writer.prepare('INSERT INTO proof VALUES(?)').run(content);writer.close();
            assert.deepEqual(sameImageFds(),originalFds,'actual Node SQLite writable descriptors must close before native sealing');
            while(!scope.sealCandidateNext()){}
            const before=fs.statSync(buildPath,{bigint:true});assert.equal(before.mode&0o7777n,0o400n);assert.equal(before.nlink,1n);
            const expected=crypto.createHash('sha256').update(fs.readFileSync(buildPath)).digest('hex');
            if(mode==='sidecar') {
              fs.writeFileSync(buildPath+'-wal','',{mode:0o600});
              assert.throws(()=>native.openPreparedImportCandidate(scope),/sealed|image/);
              assert.equal(fs.readFileSync(buildPath+'-wal').length,0);return;
            }
            const image=native.openPreparedImportCandidate(scope);
            assert.throws(()=>native.openPreparedImportCandidate(scope,buildPath),/descriptor|path|filesystem/);
            assert.throws(()=>image.verifyNext.call({}),/original|receiver/);
            let openingCalls=0;do{openingCalls++;}while(!image.verifyNext());assert(openingCalls>1);
            assert.equal(image.identity().sha256,expected);assert.equal(image.identity().byteCount,Number(before.size));
            if(mode!=='normal') {
              if(mode==='hardlink')fs.linkSync(buildPath,buildPath+'-extra');
              if(mode==='replacement'){fs.renameSync(buildPath,buildPath+'-old');fs.copyFileSync(buildPath+'-old',buildPath);fs.chmodSync(buildPath,0o400);}
              if(mode==='changed_bytes'){fs.chmodSync(buildPath,0o600);const fd=fs.openSync(buildPath,'r+');fs.writeSync(fd,Buffer.from([0]),0,1,120);fs.closeSync(fd);fs.chmodSync(buildPath,0o400);}
              assert.throws(()=>image.assertHeld(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
              assert.throws(()=>image.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
              assert.throws(()=>owner.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');return;
            }
            image.beginRead();
            const bootstrap=new DatabaseSync(':memory:',{allowExtension:true});bootstrap.loadExtension(${JSON.stringify(helper)},'sqlite3_cliqownedimportpreview_init');bootstrap.enableLoadExtension(false);bootstrap.close();
            const db=new DatabaseSync('file:cliq-owned-import-preview?vfs=cliq-owned-import-preview-v1&mode=ro&immutable=1',{readOnly:true,allowExtension:false});
            db.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA query_only=ON; PRAGMA trusted_schema=OFF');
            const policy=await import(${JSON.stringify(policy)});db.enableDefensive(true);db.setAuthorizer(policy.preparedImportReadonlyAuthorizer);
            assert.equal(db.prepare('SELECT value FROM proof').get().value,content);
            for(const sql of ["ATTACH ':memory:' AS escaped",'CREATE TEMP TABLE escaped(x)', 'PRAGMA writable_schema=ON', 'DELETE FROM proof'])assert.throws(()=>db.exec(sql));
            assert.throws(()=>new DatabaseSync('file:other-name?vfs=cliq-owned-import-preview-v1&mode=ro',{readOnly:true}));
            assert.throws(()=>image.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
            assert.throws(()=>scope.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
            assert.throws(()=>bound.close(),e=>e.code==='ERR_CLIQ_RESOURCE_RETIREMENT');
            assert.equal(db.prepare('SELECT value FROM proof').get().value,content);
            const originalStatement=db.prepare('SELECT value FROM proof'), cursor=originalStatement.iterate();
            assert.equal(cursor.next().value.value,content);cursor.return();
            db.close();image.endRead();let closingCalls=0;do{closingCalls++;}while(!image.verifyNext());assert.equal(closingCalls,openingCalls);
            image.close();scope.assertHeld();
            if(mode==='normal')assert.throws(()=>scope.beginContextProjection(),/projection requires/);
            scope.close();bound.assertHeld();bound.close();owner.assertHeld();owner.close();gate.assertHeld();gate.close();
            assert.equal(crypto.createHash('sha256').update(fs.readFileSync(buildPath)).digest('hex'),expected);
          })().catch(error=>{console.error(error);process.exitCode=1;});
        `], { encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
        assert.equal(result.error, undefined, mode); assert.equal(result.signal, null, `${mode}: ${result.stderr}`);
        assert.equal(result.status, 0, `${mode}: ${result.stderr}`);
      }
    } catch (error) { caseFailed = true; caseFailure = error; }
    try {
      await writableOwnedFixtureDirectories(fixture, user.uid);
      await rm(fixture, { recursive: true, force: true });
    } catch (cleanup) {
      if (caseFailed) throw new AggregateError([caseFailure, cleanup], 'native campaign failed; owned fixture cleanup also failed', { cause: caseFailure });
      throw cleanup;
    }
    if (caseFailed) throw caseFailure;
  });
