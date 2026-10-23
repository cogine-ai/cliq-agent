// Real filesystem mechanisms in an independent native build. These tests
// create no StateOwner, Run, SQL progress, takeover or permission evidence.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { openHeldPublicationNamespaceObserver, readRetiredPublicationNamespace, retireHeldPublicationNamespace,
  type HeldStateOwnerLock, type HeldWorkspaceRoot } from './native-owner.js';

let home: string, binary: string;
before(async () => {
  home = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-namespace-')));
  binary = path.join(home, 'fault.node');
  const includes = JSON.parse(execFileSync(process.execPath, [fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)),
    '--print-includes'], { encoding: 'utf8' })) as string[];
  const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']), ...includes.flatMap(include => ['-I', include]),
    fileURLToPath(new URL('./testing/publication-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(built.status, 0, built.stderr);
});
after(async () => { if (home) await rm(home, { recursive: true, force: true }); });

async function actual(t: TestContext, body: string) {
  const fixture = await mkdtemp(path.join(home, 'case-')), state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  t.after(() => rm(fixture, { recursive: true, force: true }));
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,lstatSync,existsSync,renameSync,mkdirSync,unlinkSync,rmdirSync,readdirSync,chmodSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);
    const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);let expectedRetirementFailure=false;
    const digest=text=>createHash('sha256').update(text).digest('hex');
    const identity=info=>({deviceId:String(info.dev),fileId:String(info.ino),ownerUid:info.uid});
    function effect(){
      writeFileSync(path.join(workspace,'file'),'old',{mode:384});
      const input={arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],
        expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'};
      const operation=lock.openPublicationOperation(root,input);while(operation.readOriginalChunk()!==null){}
      operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}operation.arm();operation.commit();
      while(operation.readPreimageChunk()!==null){}while(operation.readDestinationChunk()!==null){}
      const observed=operation.observe(),arena=path.join(state,'runtime','publications',input.arenaId);
      const observationInput={arenaId:input.arenaId,arenaIdentity:{...observed.arena.identity,mode:448},parentIdentity:observed.arena.parentIdentity,
        path:input.path,parents:input.parents,desired:input.desired,destinationIdentity:observed.destination.identity,
        stagingName:input.stagingName,quarantineName:input.quarantineName,retainedPreimage:observed.quarantine.identity};
      return {operation,observed,arena,observationInput};
    }
    try{${body}}finally{root.close();if(expectedRetirementFailure)assert.throws(()=>lock.close(),{code:'ERR_CLIQ_RESOURCE_RETIREMENT'});else lock.close();}
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

test('registered namespace observation preserves an empty original arena until separate joined retirement', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,arena,observationInput}=effect();native.setFault('fsync',1,()=>5);assert.throws(()=>operation.finishCleanup());operation.close();
    const before=lstatSync(arena),observer=lock.openPublicationNamespaceObserver(root,observationInput);let syncs=0;
    native.setFault('fsync',1,()=>{syncs++;return 5});
    const observed=observer.observe();assert.equal(observed.state,'original_arena_empty');
    assert.equal(lstatSync(arena).ino,before.ino);assert.deepEqual(readdirSync(arena),[]);
    assert.throws(()=>observer.retireNamespace());while(observer.readDestinationChunk()!==null){}
    assert.equal(syncs,0);assert.throws(()=>observer.retireNamespace());assert.equal(syncs,1);
    observer.retireNamespace();assert.equal(existsSync(arena),false);assert.throws(()=>observer.assertNamespaceRetired());
    observer.close();const witness=observer.assertNamespaceRetired();
    assert.deepEqual(witness,{kind:'namespace_absence',arenaId:observationInput.arenaId,parentIdentity:observationInput.parentIdentity,
      arenaAbsent:true,arenaParentFsyncCompleted:true,workspaceParentFsyncCompleted:true});
    assert.equal(readFileSync(path.join(workspace,'file'),'utf8'),'new');
    console.log(JSON.stringify({readOnly:true,retired:true,joined:true,oldUnlinkNotInvented:!('retirementObservation'in witness)}));
  `), { readOnly: true, retired: true, joined: true, oldUnlinkNotInvented: true });
});

test('namespace friends reject structural locks and roots before input getters', () => {
  const hostile = Object.defineProperty({}, 'arenaId', { get() { assert.fail('structural handles cannot read namespace input'); } });
  assert.throws(() => openHeldPublicationNamespaceObserver({} as HeldStateOwnerLock, {} as HeldWorkspaceRoot, hostile as never),
    /actual StateOwner and workspace handles/);
  assert.throws(() => retireHeldPublicationNamespace({} as HeldStateOwnerLock, hostile as never), /genuine same-lock observer/);
  assert.throws(() => readRetiredPublicationNamespace({} as HeldStateOwnerLock, hostile as never), /genuine same-lock observer/);
});

test('joined namespace diagnostics retain only the first real fsync interval in three fixed roles', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,observationInput}=effect();operation.finishCleanup();operation.close();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);
    assert.throws(()=>observer.readRetirementDiagnostic());while(observer.readDestinationChunk()!==null){}
    native.setFault('fsync',1,()=>4);observer.retireNamespace();
    assert.throws(()=>observer.readRetirementDiagnostic());observer.close();assert.throws(()=>observer.readRetirementDiagnostic());
    observer.assertNamespaceRetired();const spans=observer.readRetirementDiagnostic();
    assert.equal(spans.length,3);assert.deepEqual(spans.map(row=>row.slice(0,3)),[[1,2,'interrupted'],[1,1,'ok'],[1,1,'ok']]);
    for(const row of spans){assert.equal(row.length,7);for(const stamp of row.slice(3))assert.match(stamp,/^(0|[1-9][0-9]{0,19})$/);
      assert(BigInt(row[5])>=BigInt(row[3]));}
    const unchanged=structuredClone(spans);observer.assertNamespaceRetired();assert.deepEqual(observer.readRetirementDiagnostic(),unchanged);
    assert.equal(readFileSync(path.join(workspace,'file'),'utf8'),'new');
    console.log(JSON.stringify({firstInterval:true,actualEintrRetried:true,threeFixedRoles:true,postJoinOnly:true}));
  `), { firstInterval: true, actualEintrRetried: true, threeFixedRoles: true, postJoinOnly: true });
});

test('an unavailable diagnostic clock cannot change the original fsync failure or its later real retry', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,observationInput}=effect();operation.finishCleanup();operation.close();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);while(observer.readDestinationChunk()!==null){}
    native.setFault('fsync',1,()=>{native.setFault('clock',1,()=>4);return 5});
    assert.throws(()=>observer.retireNamespace());observer.retireNamespace();observer.close();observer.assertNamespaceRetired();
    const spans=observer.readRetirementDiagnostic();assert.deepEqual(spans[0],[2,2,'unavailable']);
    assert.deepEqual(spans.slice(1).map(row=>row.slice(0,3)),[[1,1,'ok'],[1,1,'ok']]);
    assert.equal(readFileSync(path.join(workspace,'file'),'utf8'),'new');
    console.log(JSON.stringify({originalFailurePreserved:true,realRetry:true,clockOnlyUnavailable:true}));
  `), { originalFailurePreserved: true, realRetry: true, clockOnlyUnavailable: true });
});

test('a post-join diagnostic does not open filesystem resources or consume the next genuine proof close failure', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,observationInput}=effect();operation.finishCleanup();operation.close();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);while(observer.readDestinationChunk()!==null){}
    observer.retireNamespace();observer.close();observer.assertNamespaceRetired();const before=observer.readRetirementDiagnostic();
    native.setFault('close',1,()=>5);assert.deepEqual(observer.readRetirementDiagnostic(),before);
    assert.throws(()=>observer.assertNamespaceRetired(),{code:'ERR_CLIQ_RESOURCE_RETIREMENT'});
    assert.throws(()=>observer.readRetirementDiagnostic());expectedRetirementFailure=true;
    console.log(JSON.stringify({snapshotOnly:true,noDiagnosticOpenClose:true,genuineProofFailurePreserved:true}));
  `), { snapshotOnly: true, noDiagnosticOpenClose: true, genuineProofFailurePreserved: true });
});

test('an already absent registered arena requires fresh real parent fsync and joined handles', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,arena,observationInput}=effect();operation.finishCleanup();
    native.setFault('fsync',2,()=>5);assert.throws(()=>operation.finishArenaRetirement());assert.equal(existsSync(arena),false);operation.close();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);assert.equal(observer.observe().state,'arena_absent');
    while(observer.readDestinationChunk()!==null){}
    native.setFault('fsync',1,()=>5);assert.throws(()=>observer.retireNamespace());
    native.setFault('fsync',1,()=>5);assert.throws(()=>observer.retireNamespace());
    observer.retireNamespace();observer.close();assert.equal(observer.assertNamespaceRetired().kind,'namespace_absence');
    console.log(JSON.stringify({currentAbsence:true,fsyncReallyRetried:true,joined:true}));
  `), { currentAbsence: true, fsyncReallyRetried: true, joined: true });
});

test('namespace observation refuses foreign arenas, parents, preimages, extra entries and missing original identities without mutation', async t => {
  for (const mutation of [
    "operation.finishCleanup();operation.close();renameSync(arena,arena+'.captured');mkdirSync(arena,{mode:448});writeFileSync(path.join(arena,'foreign'),'keep')",
    "operation.finishCleanup();operation.close();renameSync(path.dirname(arena),path.dirname(arena)+'.captured');mkdirSync(path.dirname(arena),{mode:448})",
    "operation.close();renameSync(path.join(arena,'.old'),path.join(arena,'.captured'));writeFileSync(path.join(arena,'.old'),'old',{mode:384})",
    "operation.finishCleanup();operation.close();writeFileSync(path.join(arena,'extra'),'keep')",
    "operation.close();delete observationInput.retainedPreimage",
    "operation.finishCleanup();operation.close();delete observationInput.arenaIdentity",
    "operation.finishCleanup();operation.close();chmodSync(arena,493)",
    "operation.finishCleanup();operation.close();chmodSync(path.dirname(arena),493)",
    "operation.finishCleanup();operation.close();renameSync(path.join(workspace,'file'),path.join(workspace,'file.captured'));writeFileSync(path.join(workspace,'file'),'new',{mode:420})",
    "operation.finishCleanup();operation.close();chmodSync(path.join(workspace,'file'),384)"
  ]) {
    assert.deepEqual(await actual(t, `
      const {operation,arena,observationInput}=effect();${mutation};
      const names=existsSync(arena)?readdirSync(arena):null;
      assert.throws(()=>lock.openPublicationNamespaceObserver(root,observationInput));
      assert.deepEqual(existsSync(arena)?readdirSync(arena):null,names);assert.equal(readFileSync(path.join(workspace,'file'),'utf8'),'new');
      console.log(JSON.stringify({refused:true,untouched:true}));
    `), { refused: true, untouched: true });
  }
});

test('namespace reads hash every file chunk and read the symlink itself without following its target', async t => {
  assert.deepEqual(await actual(t, `
    const payload=Buffer.alloc(65537,97),parents=[{...root.identity,mode:root.mode}];
    for(const [index,desired]of [{kind:'file',mode:420,byteCount:payload.length,digest:digest(payload)},
      {kind:'symlink',target:'target',digest:digest('target')}].entries()){
      writeFileSync(path.join(workspace,'target'),'not the raw link bytes');
      const pathName='entry'+index,arenaId=String.fromCharCode(65+index).repeat(43),operation=lock.openPublicationOperation(root,
        {arenaId,kind:'create',path:pathName,parents,expected:{kind:'absent'},desired,stagingName:'.stage'});
      operation.stage();if(desired.kind==='file'){operation.writeChunk(payload.subarray(0,65536));operation.writeChunk(payload.subarray(65536))}
      while(!operation.finishStage()){}operation.arm();operation.commit();while(operation.readDestinationChunk()!==null){}
      const observed=operation.observe();operation.finishCleanup();operation.close();
      const observer=lock.openPublicationNamespaceObserver(root,{arenaId,path:pathName,parents,desired,stagingName:'.stage',
        arenaIdentity:{...observed.arena.identity,mode:448},parentIdentity:observed.arena.parentIdentity,destinationIdentity:observed.destination.identity});
      const chunks=[];for(;;){const bytes=observer.readDestinationChunk();if(bytes===null)break;chunks.push(bytes)}
      assert.deepEqual(Buffer.concat(chunks),desired.kind==='file'?payload:Buffer.from('target'));
      if(desired.kind==='file')assert.deepEqual(chunks.map(bytes=>bytes.length),[65536,1]);
      assert.equal(observer.observe().destination.digest,desired.digest);observer.retireNamespace();observer.close();assert.equal(observer.assertNamespaceRetired().arenaAbsent,true);
    }
    console.log(JSON.stringify({completeFile:true,rawSymlink:true,boundedChunks:true}));
  `), { completeFile: true, rawSymlink: true, boundedChunks: true });
});

test('namespace observation supports actual absent and directory destinations without making file or tree claims', async t => {
  assert.deepEqual(await actual(t, `
    const parents=[{...root.identity,mode:root.mode}];
    for(const [index,kind]of ['delete','mkdir'].entries()){
      const pathName='entry'+index,arenaId=String.fromCharCode(65+index).repeat(43);if(kind==='delete')writeFileSync(path.join(workspace,pathName),'old',{mode:384});
      const desired=kind==='delete'?{kind:'absent'}:{kind:'directory',mode:493};
      const operation=lock.openPublicationOperation(root,{arenaId,kind,path:pathName,parents,desired,
        expected:kind==='delete'?{kind:'file',mode:384,byteCount:3,digest:digest('old')}:{kind:'absent'},...(kind==='delete'?{quarantineName:'.old'}:{})});
      if(kind==='delete')while(operation.readOriginalChunk()!==null){}operation.stage();while(!operation.finishStage()){}operation.arm();operation.commit();
      if(kind==='delete')while(operation.readPreimageChunk()!==null){}else while(operation.readDestinationChunk()!==null){}
      const observed=operation.observe();operation.finishCleanup();operation.close();
      const observer=lock.openPublicationNamespaceObserver(root,{arenaId,path:pathName,parents,desired,
        ...(kind==='delete'?{quarantineName:'.old'}:{stagingName:'desired',destinationIdentity:observed.destination.identity}),
        arenaIdentity:{...observed.arena.identity,mode:448},parentIdentity:observed.arena.parentIdentity});
      assert.equal(observer.readDestinationChunk(),null);assert.equal(observer.observe().destination.kind,desired.kind);
      observer.retireNamespace();observer.close();assert.equal(observer.assertNamespaceRetired().kind,'namespace_absence');
    }
    console.log(JSON.stringify({actualAbsent:true,actualDirectory:true,noFileHashInvented:true}));
  `), { actualAbsent: true, actualDirectory: true, noFileHashInvented: true });
});

test('namespace desired reads retain exact inode, raw mode, bytes and disjoint native role tags', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,arena,observationInput}=effect();operation.finishCleanup();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);
    assert.throws(()=>operation.arm.call(observer));assert.throws(()=>operation.commit.call(observer));assert.throws(()=>operation.finishCleanup.call(observer));
    assert.equal('arm'in observer,false);assert.equal('commit'in observer,false);operation.close();
    while(observer.readDestinationChunk()!==null){}writeFileSync(path.join(workspace,'file'),'bad');
    assert.throws(()=>observer.observe());assert.throws(()=>observer.retireNamespace());observer.close();
    assert.equal(existsSync(arena),true);assert.equal(readFileSync(path.join(workspace,'file'),'utf8'),'bad');
    const mismatched=lock.openPublicationNamespaceObserver(root,observationInput);
    assert.throws(()=>{while(mismatched.readDestinationChunk()!==null){}});assert.throws(()=>mismatched.retireNamespace());mismatched.close();
    console.log(JSON.stringify({nativeTagsDisjoint:true,driftRefused:true,noRelease:true}));
  `), { nativeTagsDisjoint: true, driftRefused: true, noRelease: true });
});

test('uncertain namespace close cannot produce a joined absence witness or release its StateOwner', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,observationInput}=effect();operation.finishCleanup();operation.finishArenaRetirement();operation.close();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);while(observer.readDestinationChunk()!==null){}observer.retireNamespace();
    native.setFault('close',1,()=>5);assert.throws(()=>observer.close(),{code:'ERR_CLIQ_RESOURCE_RETIREMENT'});
    assert.throws(()=>observer.assertNamespaceRetired(),{code:'ERR_CLIQ_RESOURCE_RETIREMENT'});expectedRetirementFailure=true;
    console.log(JSON.stringify({joinedWitnessRefused:true,stateOwnerRetained:true}));
  `), { joinedWitnessRefused: true, stateOwnerRetained: true });
});

test('post-join namespace observation refuses a substituted original parent and never repairs it', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,arena,observationInput}=effect();operation.finishCleanup();operation.finishArenaRetirement();operation.close();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);while(observer.readDestinationChunk()!==null){}observer.retireNamespace();observer.close();
    const parent=path.dirname(arena);renameSync(parent,parent+'.captured');mkdirSync(parent,{mode:448});
    assert.throws(()=>observer.assertNamespaceRetired());assert.deepEqual(readdirSync(parent),[]);assert.equal(existsSync(parent+'.captured'),true);
    console.log(JSON.stringify({parentDriftRefused:true,foreignPreserved:true}));
  `), { parentDriftRefused: true, foreignPreserved: true });
});

test('the final namespace recheck also joins its temporary descriptor before returning a witness', async t => {
  for (const point of ['close', 'namespace_parent_close']) {
    assert.deepEqual(await actual(t, `
      const {operation,observationInput}=effect();operation.finishCleanup();operation.finishArenaRetirement();operation.close();
      const observer=lock.openPublicationNamespaceObserver(root,observationInput);while(observer.readDestinationChunk()!==null){}observer.retireNamespace();observer.close();
      native.setFault('${point}',1,()=>5);assert.throws(()=>observer.assertNamespaceRetired(),{code:'ERR_CLIQ_RESOURCE_RETIREMENT'});expectedRetirementFailure=true;
      console.log(JSON.stringify({temporaryJoinFailureRetained:true,noWitness:true}));
    `), { temporaryJoinFailureRetained: true, noWitness: true });
  }
});

test('only an exact registered preimage routes to the unchanged retained cleanup mechanism', async t => {
  assert.deepEqual(await actual(t, `
    const {operation,arena,observed,observationInput}=effect();operation.revoke();operation.close();
    const observer=lock.openPublicationNamespaceObserver(root,observationInput);
    assert.equal(observer.observe().state,'original_slots_present');assert.throws(()=>observer.retireNamespace());
    assert.equal(readFileSync(path.join(arena,'.old'),'utf8'),'old');observer.close();assert.throws(()=>observer.assertNamespaceRetired());
    const retained=lock.openPublicationOperation(root,{arenaId:observationInput.arenaId,kind:'replace',path:'file',parents:observationInput.parents,
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:observationInput.desired,stagingName:'.stage',quarantineName:'.old',
      retained:{arena:observed.arena.identity,destination:observed.destination.identity,preimage:observed.quarantine.identity}});
    assert.throws(()=>retained.arm());while(retained.readPreimageChunk()!==null){}while(retained.readDestinationChunk()!==null){}
    retained.finishCleanup();retained.finishArenaRetirement();retained.close();assert.equal(existsSync(arena),false);
    console.log(JSON.stringify({routed:true,noNamespaceCleanup:true,oldRetainedGuard:true}));
  `), { routed: true, noNamespaceCleanup: true, oldRetainedGuard: true });
});
