// Real compiled native filesystem mechanism; no approval, Run, Journal,
// installed launch or recovery authority is supplied by these physical tests.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadNativeStateOwner } from './native-owner.js';

async function faultFixture(t: import('node:test').TestContext) {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-fault-')));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  const binary = path.join(fixture, 'fault.node'), state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const includes = JSON.parse(execFileSync(process.execPath, [fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'], { encoding: 'utf8' })) as string[];
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']), ...includes.flatMap(include => ['-I', include]),
    fileURLToPath(new URL('./testing/publication-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr);
  return { binary, state, workspace };
}

test('a held workspace root reports its actual current link count and rejects replaced, closed or structural receivers', async t => {
  const { binary, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';import {Module} from 'node:module';import {lstatSync,mkdirSync,renameSync} from 'node:fs';import path from 'node:path';
    const [binary,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const root=native.openWorkspaceRoot(workspace),identity={...root.identity};
    try {
      assert.equal(root.linkCount,lstatSync(workspace).nlink);mkdirSync(path.join(workspace,'child'),{mode:448});
      assert.equal(root.linkCount,lstatSync(workspace).nlink);assert.deepEqual(root.identity,identity);
      const get=Object.getOwnPropertyDescriptor(root,'linkCount').get;assert.throws(()=>get.call({}));
      renameSync(workspace,workspace+'.captured');mkdirSync(workspace,{mode:448});assert.throws(()=>root.linkCount);
    } finally {root.close();}
    assert.throws(()=>root.linkCount);console.log(JSON.stringify({actual:true,identityUnchanged:true,replacedAndClosedRefused:true}));
  `, binary, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { actual: true, identityUnchanged: true, replacedAndClosedRefused: true });
});

test('abort maintenance quarantines only its exact published empty directory before native cleanup', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {lstatSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),parents=[{...root.identity,mode:root.mode}];
    const creator=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'mkdir',path:'directory',parents,expected:{kind:'absent'},desired:{kind:'directory',mode:493}});
    creator.stage();creator.finishStage();creator.arm();creator.commit();while(creator.readDestinationChunk()!==null){}creator.finishCleanup();creator.finishArenaRetirement();creator.revoke();
    let rearmRefused=false;try{creator.arm()}catch{rearmRefused=true}creator.close();
    const before=lstatSync(path.join(workspace,'directory'));
    const operation=lock.openPublicationOperation(root,{arenaId:'B'.repeat(43),kind:'abort_rmdir',path:'directory',parents,
      expected:{kind:'directory',mode:before.mode&4095,identity:{deviceId:String(before.dev),fileId:String(before.ino),ownerUid:before.uid}},desired:{kind:'absent'},quarantineName:'preimage'});
    while(operation.readOriginalChunk()!==null){}operation.stage();operation.finishStage();
    let unarmedRefused=false;try{operation.commit()}catch{unarmedRefused=true}operation.arm();operation.commit();
    const quarantine=path.join(state,'runtime','publications','B'.repeat(43),'preimage');
    const quarantined=lstatSync(quarantine).ino===before.ino&&!existsSync(path.join(workspace,'directory'));
    let unpreservedRefused=false;try{operation.finishCleanup()}catch{unpreservedRefused=true}
    // Physical component only: reading the empty preimage is not a durable SQL
    // barrier. The sole production producer must supply that separate brand.
    while(operation.readPreimageChunk()!==null){}operation.revoke();operation.finishCleanup();operation.finishArenaRetirement();operation.close();
    const retired=!existsSync(path.dirname(quarantine));root.close();lock.close();
    console.log(JSON.stringify({rearmRefused,unarmedRefused,quarantined,unpreservedRefused,retired}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { rearmRefused: true, unarmedRefused: true, quarantined: true, unpreservedRefused: true, retired: true });
});

test('abort maintenance retains a foreign or newly nonempty directory at the last quarantine cut', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {mkdirSync,lstatSync,renameSync,writeFileSync,readFileSync,readdirSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),results=[];
    for(const [index,[replace,unexpected]] of [[true,true],[false,true],[true,false]].entries()){
      const name='directory'+index,arenaId=String.fromCharCode(65+index).repeat(43),directory=path.join(workspace,name);mkdirSync(directory,{mode:493});const original=lstatSync(directory);
      const operation=lock.openPublicationOperation(root,{arenaId,kind:'abort_rmdir',path:name,parents:[{...root.identity,mode:root.mode}],
        expected:{kind:'directory',mode:493,identity:{deviceId:String(original.dev),fileId:String(original.ino),ownerUid:original.uid}},desired:{kind:'absent'},quarantineName:'preimage'});
      while(operation.readOriginalChunk()!==null){}operation.stage();operation.finishStage();operation.arm();let actual;
      native.setFault('before_rename',1,()=>{if(replace){renameSync(directory,directory+'.created');mkdirSync(directory,{mode:493})}if(unexpected)writeFileSync(path.join(directory,'unexpected'),'retain');actual=lstatSync(directory).ino;return 0});
      let refused=false,cleanupRefused=false,expectedRefused=false,reconcileRefused=false;
      try{operation.commit()}catch{refused=true}operation.revoke();try{operation.finishCleanup()}catch{cleanupRefused=true}
      try{operation.readPreimageChunk()}catch{expectedRefused=true}try{operation.reconcile()}catch{reconcileRefused=true}
      const quarantine=path.join(state,'runtime','publications',arenaId,'preimage'),description=operation.describeActualPreimage();
      results.push({refused,cleanupRefused,expectedRefused,reconcileRefused,retained:lstatSync(quarantine).ino===actual&&(unexpected?readFileSync(path.join(quarantine,'unexpected'),'utf8')==='retain':readdirSync(quarantine).length===0),
        actual:description.kind==='directory'&&description.identity.fileId===String(actual)&&description.empty===!unexpected,originalRetained:!replace||lstatSync(directory+'.created').ino===original.ino,absent:!existsSync(directory)});
      operation.close();
    }
    root.close();lock.close();console.log(JSON.stringify(results));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  const expected = { refused: true, cleanupRefused: true, expectedRefused: true, reconcileRefused: true,
    retained: true, actual: true, originalRetained: true, absent: true };
  assert.deepEqual(JSON.parse(observed.stdout), [expected, expected, expected]);
});

test('abort maintenance never gains file, alternate-slot, staging or revoked-release capability', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';import {mkdirSync,lstatSync,writeFileSync,readFileSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),parents=[{...root.identity,mode:root.mode}];
    mkdirSync(path.join(workspace,'directory'),{mode:493});const original=lstatSync(path.join(workspace,'directory'));
    const input={arenaId:'A'.repeat(43),kind:'abort_rmdir',path:'directory',parents,expected:{kind:'directory',mode:493,identity:{deviceId:String(original.dev),fileId:String(original.ino),ownerUid:original.uid}},desired:{kind:'absent'},quarantineName:'preimage'};
    writeFileSync(path.join(workspace,'file'),'keep',{mode:384});const digest=createHash('sha256').update('keep').digest('hex');let refused=0;
    for(const patch of [{path:'file',expected:{kind:'file',mode:384,byteCount:4,digest}},{desired:{kind:'file',mode:420,byteCount:4,digest}},{quarantineName:'other'},{stagingName:'desired'},
      {expected:{...input.expected,identity:{...input.expected.identity,fileId:String(original.ino+1)}}}]){try{lock.openPublicationOperation(root,{...input,...patch}).close()}catch{refused++}}
    const operation=lock.openPublicationOperation(root,input);while(operation.readOriginalChunk()!==null){}operation.stage();operation.finishStage();operation.arm();operation.revoke();
    let rearmRefused=false,commitRefused=false;try{operation.arm()}catch{rearmRefused=true}try{operation.commit()}catch{commitRefused=true}
    operation.discardStage();operation.finishArenaRetirement();operation.close();
    const unchanged=lstatSync(path.join(workspace,'directory')).ino===original.ino&&readFileSync(path.join(workspace,'file'),'utf8')==='keep'&&!existsSync(path.join(state,'runtime','publications','A'.repeat(43)));
    root.close();lock.close();console.log(JSON.stringify({refused,rearmRefused,commitRefused,unchanged}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { refused: 5, rearmRefused: true, commitRefused: true, unchanged: true });
});

test('abort maintenance refuses an already nonempty directory without moving or removing its children', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {mkdirSync,lstatSync,writeFileSync,readFileSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),directory=path.join(workspace,'directory');mkdirSync(directory,{mode:493});writeFileSync(path.join(directory,'child'),'keep');const original=lstatSync(directory);
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'abort_rmdir',path:'directory',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'directory',mode:493,identity:{deviceId:String(original.dev),fileId:String(original.ino),ownerUid:original.uid}},desired:{kind:'absent'},quarantineName:'preimage'});
    let readRefused=false,stageRefused=false,commitRefused=false;try{operation.readOriginalChunk()}catch{readRefused=true}try{operation.stage()}catch{stageRefused=true}operation.arm();try{operation.commit()}catch{commitRefused=true}
    operation.discardStage();operation.finishArenaRetirement();operation.close();
    const retained=lstatSync(directory).ino===original.ino&&readFileSync(path.join(directory,'child'),'utf8')==='keep'&&!existsSync(path.join(state,'runtime','publications','A'.repeat(43)));
    root.close();lock.close();console.log(JSON.stringify({readRefused,stageRefused,commitRefused,retained}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { readRefused: true, stageRefused: true, commitRefused: true, retained: true });
});

test('native directory read failure is not presented as a nonempty observation', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { Module } from 'node:module';
    const [binary, state, workspace] = process.argv.slice(1);
    const module = new Module(binary); process.dlopen(module, binary);
    const native = module.exports, lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
    const operation = lock.openPublicationOperation(root,{arenaId:'A'.repeat(43), kind:'mkdir', path:'directory', parents:[{...root.identity,mode:root.mode}], expected:{kind:'absent'}, desired:{kind:'directory',mode:493} });
    operation.arm();operation.stage(); operation.finishStage(); operation.commit();
    native.setFault('readdir',1,()=>5);
    let errorCode; try { operation.observe(); } catch(error) { errorCode=error.code; }
    operation.close(); root.close(); lock.close();
    console.log(JSON.stringify({errorCode}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { errorCode: 'ERR_CLIQ_STATE_OWNER_NATIVE' });
});

test('readonly inspection leaves a lost-ack displaced staging inode untouched until explicit original maintenance', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,lstatSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=text=>createHash('sha256').update(text).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});const original=lstatSync(path.join(workspace,'file'));
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
    native.setFault('after_rename',1,()=>5);assert.throws(()=>operation.commit());operation.revoke();
    const arena=path.join(state,'runtime','publications','A'.repeat(43)),staging=path.join(arena,'.stage'),quarantine=path.join(arena,'.old');
    const fields=['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'];
    const snapshot=()=>[workspace,arena,path.join(workspace,'file'),staging].map(name=>{const info=lstatSync(name,{bigint:true});return fields.map(key=>String(info[key]))});
    const before=snapshot();let maintenanceRenames=0;native.setFault('before_rename',1,()=>{maintenanceRenames++;return 0});
    const status=operation.inspectState();assert.deepEqual(snapshot(),before);assert.equal(maintenanceRenames,0);
    assert.equal(lstatSync(staging).ino,original.ino);assert.equal(existsSync(quarantine),false);
    assert.equal(readFileSync(path.join(workspace,'file'),'utf8'),'new');assert.equal(readFileSync(staging,'utf8'),'old');
    assert.throws(()=>operation.arm());assert.throws(()=>operation.commit());
    const reconciled=operation.reconcile();assert.equal(maintenanceRenames,1);assert.equal(lstatSync(quarantine).ino,original.ino);
    while(operation.readDestinationChunk()!==null){}while(operation.readPreimageChunk()!==null){}operation.finishCleanup();operation.finishArenaRetirement();operation.close();root.close();lock.close();
    console.log(JSON.stringify({status,reconciled,namespaceUnchangedByInspection:true,explicitMaintenanceMovedOriginal:true,arenaRetired:!existsSync(arena)}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { status: 'effect_present', reconciled: 'committed',
    namespaceUnchangedByInspection: true, explicitMaintenanceMovedOriginal: true, arenaRetired: true });
});

test('readonly inspection distinguishes unpublished, committed and cleaned originals and refuses foreign destinations', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,lstatSync,existsSync,renameSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=text=>createHash('sha256').update(text).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),results=[];
    for(const [index,[deleting,foreign]] of [[false,false],[true,false],[false,true]].entries()){
      const name='file'+index,target=path.join(workspace,name),arenaId=String.fromCharCode(65+index).repeat(43);writeFileSync(target,'old',{mode:384});
      const common={arenaId,path:name,parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},quarantineName:'preimage'};
      const operation=lock.openPublicationOperation(root,deleting?{...common,kind:'delete',desired:{kind:'absent'}}:
        {...common,kind:'replace',desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'desired'});
      assert.equal(operation.inspectState(),'unstarted');while(operation.readOriginalChunk()!==null){}operation.stage();
      if(!deleting)operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}assert.equal(operation.inspectState(),'unstarted');
      operation.restartRead('inspection_original');const reread=[];for(;;){const bytes=operation.readInspectionOriginalChunk();if(bytes===null)break;reread.push(bytes)}
      assert.equal(Buffer.concat(reread).toString('utf8'),'old');
      operation.arm();operation.commit();operation.revoke();assert.equal(operation.inspectState(),'effect_present');
      assert.throws(()=>operation.arm());assert.throws(()=>operation.commit());
      if(foreign){const published=target+'.published';renameSync(target,published);writeFileSync(target,'foreign',{mode:420});
        const replacement=lstatSync(target);assert.throws(()=>operation.inspectState());assert.equal(lstatSync(target).ino,replacement.ino);assert.equal(readFileSync(target,'utf8'),'foreign');
        assert.throws(()=>operation.finishCleanup());operation.close();results.push({deleting,foreign:true,retired:false,foreignPreserved:true});continue;}
      if(!deleting)while(operation.readDestinationChunk()!==null){}while(operation.readPreimageChunk()!==null){}operation.finishCleanup();
      assert.equal(operation.inspectState(),'cleaned');operation.finishArenaRetirement();assert.equal(operation.inspectState(),'cleaned');operation.close();
      assert.throws(()=>operation.inspectState());results.push({deleting,foreign:false,retired:!existsSync(path.join(state,'runtime','publications',arenaId)),foreignPreserved:true});
    }
    root.close();lock.close();console.log(JSON.stringify(results));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), [
    { deleting: false, foreign: false, retired: true, foreignPreserved: true },
    { deleting: true, foreign: false, retired: true, foreignPreserved: true },
    { deleting: false, foreign: true, retired: false, foreignPreserved: true },
  ]);
});

test('a retained native cleanup handle stays release-fenced and inspection never invents a replacement inode', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,lstatSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=text=>createHash('sha256').update(text).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    let lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const input={arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'desired',quarantineName:'preimage'};
    const original=lock.openPublicationOperation(root,input);while(original.readOriginalChunk()!==null){}original.stage();original.writeChunk(Buffer.from('new'));while(!original.finishStage()){}
    original.arm();original.commit();while(original.readDestinationChunk()!==null){}while(original.readPreimageChunk()!==null){}const actual=original.observe();
    const inode=value=>({deviceId:value.deviceId,fileId:value.fileId}),retained={arena:inode(actual.arena.identity),destination:inode(actual.destination.identity),preimage:inode(actual.quarantine.identity)};
    original.close();root.close();lock.close();lock=native.acquireLock(state,false);root=native.openWorkspaceRoot(workspace);
    assert.throws(()=>lock.openPublicationOperation(root,{...input,retained:{...retained,destination:{...retained.destination,fileId:String(BigInt(retained.destination.fileId)+1n)}}}));
    const recovery=lock.openPublicationOperation(root,{...input,retained}),destination=lstatSync(path.join(workspace,'file')).ino;
    assert.equal(recovery.inspectState(),'effect_present');assert.equal(lstatSync(path.join(workspace,'file')).ino,destination);
    assert.throws(()=>recovery.arm());assert.throws(()=>recovery.stage());assert.throws(()=>recovery.commit());
    // Physical seam only: these actual observations and native handles are not
    // a StateOwner death, durable PathProgress barrier, or recovery authority.
    while(recovery.readDestinationChunk()!==null){}while(recovery.readPreimageChunk()!==null){}
    recovery.finishCleanup();recovery.finishArenaRetirement();recovery.close();root.close();lock.close();
    console.log(JSON.stringify({sameOriginalDestination:readFileSync(path.join(workspace,'file'),'utf8')==='new',releaseFenced:true,wrongInodeRefused:true,retired:!existsSync(path.join(state,'runtime','publications',input.arenaId))}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { sameOriginalDestination: true, releaseFenced: true, wrongInodeRefused: true, retired: true });
});

test('the original held operation reconciles a lost rename acknowledgment without a second semantic effect', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { Module } from 'node:module';
    import { createHash } from 'node:crypto';
    import { writeFileSync,readFileSync,lstatSync,existsSync } from 'node:fs';
    import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1), digest=text=>createHash('sha256').update(text).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});const old=lstatSync(path.join(workspace,'file'));
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
    native.setFault('after_rename',1,()=>5);let failed=false;try{operation.commit()}catch{failed=true}
    operation.revoke();const reconciled=operation.reconcile();
    while(operation.readDestinationChunk()!==null){}while(operation.readPreimageChunk()!==null){}
    const arena=path.join(state,'runtime','publications','A'.repeat(43));
    const sameOriginal=lstatSync(path.join(arena,'.old')).ino===old.ino;operation.finishCleanup();
    const result={failed,reconciled,sameOriginal,destination:readFileSync(path.join(workspace,'file'),'utf8'),transients:existsSync(path.join(arena,'.stage'))||existsSync(path.join(arena,'.old'))};
    operation.close();root.close();lock.close();console.log(JSON.stringify(result));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { failed: true, reconciled: 'committed', sameOriginal: true, destination: 'new', transients: false });
});

test('private directory birth cannot adopt or chmod a workspace replacement at the first-open cut', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,renameSync,mkdirSync,lstatSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=createHash('sha256').update('old').digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest},
      desired:{kind:'directory',mode:493},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}
    let foreign;
    native.setFault('after_mkdir',1,()=>{try{renameSync(path.join(workspace,'.stage'),path.join(workspace,'.born'))}catch(error){if(error.code!=='ENOENT')throw error}mkdirSync(path.join(workspace,'.stage'),{mode:448});writeFileSync(path.join(workspace,'.stage','foreign'),'do not alter');foreign=lstatSync(path.join(workspace,'.stage')).ino;return 0});
    operation.arm();operation.stage();while(!operation.finishStage()){}operation.commit();
    const result={publishedForeign:lstatSync(path.join(workspace,'file')).ino===foreign,foreignMode:lstatSync(path.join(workspace,'.stage')).mode&4095,
      foreign:readFileSync(path.join(workspace,'.stage','foreign'),'utf8'),original:readFileSync(path.join(state,'runtime','publications','A'.repeat(43),'.old'),'utf8')};
    operation.close();root.close();lock.close();console.log(JSON.stringify(result));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { publishedForeign: false, foreignMode: 0o700, foreign: 'do not alter', original: 'old' });
});

test('an uncertain publication descriptor close retains the actual StateOwner lock until process death', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),digest=createHash('sha256').update('bytes').digest('hex');
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'create',path:'file',parents:[{...root.identity,mode:root.mode}],expected:{kind:'absent'},desired:{kind:'file',mode:420,byteCount:5,digest},stagingName:'.stage'});
    operation.arm();operation.stage();operation.writeChunk(Buffer.from('bytes'));while(!operation.finishStage()){}
    native.setFault('close',1,()=>5);let operationCode,ownerCode,held=false;
    try{operation.close()}catch(error){operationCode=error.code}try{lock.close()}catch(error){ownerCode=error.code}
    try{native.acquireLock(state,false).close()}catch{held=true}
    console.log(JSON.stringify({operationCode,ownerCode,held}));process.exit(0);
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { operationCode: 'ERR_CLIQ_RESOURCE_RETIREMENT', ownerCode: 'ERR_CLIQ_RESOURCE_RETIREMENT', held: true });
  const successor = (await loadNativeStateOwner()).acquireLock(state, false); successor.close();
});

test('symlink birth cannot publish a same-target replacement inserted before the first descriptor open', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {renameSync,symlinkSync,lstatSync,readlinkSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),target='file',digest=createHash('sha256').update(target).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'create',path:'link',parents:[{...root.identity,mode:root.mode}],expected:{kind:'absent'},
      desired:{kind:'symlink',target,digest},stagingName:'.stage'});
    let foreign;
    native.setFault('after_symlink',1,()=>{try{renameSync(path.join(workspace,'.stage'),path.join(workspace,'.born'))}catch(error){if(error.code!=='ENOENT')throw error}symlinkSync(target,path.join(workspace,'.stage'));foreign=lstatSync(path.join(workspace,'.stage')).ino;return 0});
    let refused=false;try{operation.arm();operation.stage();while(!operation.finishStage()){}operation.commit()}catch{refused=true}
    const publishedForeign=(()=>{try{return lstatSync(path.join(workspace,'link')).ino===foreign}catch{return false}})();
    const foreignPreserved=(()=>{try{return lstatSync(path.join(workspace,'.stage')).ino===foreign&&readlinkSync(path.join(workspace,'.stage'))===target}catch{return false}})();
    operation.close();root.close();lock.close();console.log(JSON.stringify({refused,publishedForeign,foreignPreserved}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { refused: false, publishedForeign: false, foreignPreserved: true });
});

test('a last-cut staging replacement cannot publish foreign regular-file bytes', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {renameSync,writeFileSync,readFileSync,lstatSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=createHash('sha256').update('good').digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'create',path:'file',parents:[{...root.identity,mode:root.mode}],expected:{kind:'absent'},
      desired:{kind:'file',mode:420,byteCount:4,digest},stagingName:'.stage'});
    operation.arm();operation.stage();operation.writeChunk(Buffer.from('good'));while(!operation.finishStage()){}
    let foreign;
    native.setFault('before_rename',1,()=>{try{renameSync(path.join(workspace,'.stage'),path.join(workspace,'.born'))}catch(error){if(error.code!=='ENOENT')throw error}writeFileSync(path.join(workspace,'.stage'),'evil',{mode:420});foreign=lstatSync(path.join(workspace,'.stage')).ino;return 0});
    let refused=false;try{operation.commit()}catch{refused=true}
    const publishedForeign=(()=>{try{return lstatSync(path.join(workspace,'file')).ino===foreign&&readFileSync(path.join(workspace,'file'),'utf8')==='evil'}catch{return false}})();
    const foreignPreserved=(()=>{try{return lstatSync(path.join(workspace,'.stage')).ino===foreign}catch{return false}})();
    operation.close();root.close();lock.close();console.log(JSON.stringify({refused,publishedForeign,foreignPreserved}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { refused: false, publishedForeign: false, foreignPreserved: true });
});

test('a last-cut quarantine replacement cannot unlink a foreign regular-file inode', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {renameSync,writeFileSync,readFileSync,lstatSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},
      desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}operation.commit();
    while(operation.readDestinationChunk()!==null){}let originalPreserved='';for(;;){const bytes=operation.readPreimageChunk();if(bytes===null)break;originalPreserved+=bytes.toString()}
    let foreign;
    native.setFault('before_unlink',1,()=>{try{renameSync(path.join(workspace,'.old'),path.join(workspace,'.saved'))}catch(error){if(error.code!=='ENOENT')throw error}writeFileSync(path.join(workspace,'.old'),'foreign',{mode:384});foreign=lstatSync(path.join(workspace,'.old')).ino;return 0});
    let refused=false;try{operation.finishCleanup()}catch{refused=true}
    const foreignPreserved=(()=>{try{return lstatSync(path.join(workspace,'.old')).ino===foreign&&readFileSync(path.join(workspace,'.old'),'utf8')==='foreign'}catch{return false}})();
    const privatePreimageAbsent=!existsSync(path.join(state,'runtime','publications','A'.repeat(43),'.old'));
    operation.close();root.close();lock.close();console.log(JSON.stringify({refused,foreignPreserved,originalPreserved,privatePreimageAbsent}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { refused: false, foreignPreserved: true, originalPreserved: 'old', privatePreimageAbsent: true });
});

test('a last-cut destination change is retained as an ambiguous actual preimage, never cleaned as the expected inode', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {renameSync,writeFileSync,readFileSync,lstatSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},
      desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
    const actualBytes=Buffer.alloc(65536+17,255);actualBytes[0]=0;let actualPreimage;
    native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,'file'),path.join(workspace,'.captured'));writeFileSync(path.join(workspace,'file'),actualBytes,{mode:384});actualPreimage=lstatSync(path.join(workspace,'file')).ino;return 0});
    let refused=false,cleanupRefused=false;try{operation.commit()}catch{refused=true}try{operation.finishCleanup()}catch{cleanupRefused=true}
    const actualPath=path.join(state,'runtime','publications','A'.repeat(43),'.stage');
    const actualRetained=lstatSync(actualPath).ino===actualPreimage&&readFileSync(actualPath).equals(actualBytes);
    const initial=operation.describeActualPreimage();operation.revoke();operation.restartRead('actual_preimage');
    const chunks=[];for(let chunk;(chunk=operation.readActualPreimageChunk())!==null;)chunks.push(chunk);
    const streamed=Buffer.concat(chunks),complete=operation.describeActualPreimage();
    let expectedReadRefused=false,reconcileRefused=false;try{operation.readPreimageChunk()}catch{expectedReadRefused=true}try{operation.reconcile()}catch{reconcileRefused=true}
    const result={refused,cleanupRefused,expectedReadRefused,reconcileRefused,actualRetained,
      actualObserved:initial.kind==='file'&&initial.identity.fileId===String(actualPreimage)&&initial.mode===384&&initial.byteCount==='65553'&&initial.linkCount===1&&initial.digest===undefined,
      chunks:chunks.map(chunk=>chunk.length),complete:streamed.equals(actualBytes)&&complete.digest===digest(actualBytes),
      destination:readFileSync(path.join(workspace,'file'),'utf8'),captured:readFileSync(path.join(workspace,'.captured'),'utf8')};
    operation.close();root.close();lock.close();console.log(JSON.stringify(result));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { refused: true, cleanupRefused: true, expectedReadRefused: true, reconcileRefused: true,
    actualRetained: true, actualObserved: true, chunks: [65536, 17], complete: true, destination: 'new', captured: 'old' });
});

test('an unexpected delete preimage is readable from its original captured private inode only', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,renameSync,lstatSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'delete',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'absent'},quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();while(!operation.finishStage()){}
    let actual;native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,'file'),path.join(workspace,'.captured'));writeFileSync(path.join(workspace,'file'),'old',{mode:384});actual=lstatSync(path.join(workspace,'file')).ino;return 0});
    let refused=false;try{operation.commit()}catch{refused=true}operation.revoke();const chunks=[];for(let bytes;(bytes=operation.readActualPreimageChunk())!==null;)chunks.push(bytes);
    const actualState=operation.describeActualPreimage();let cleanupRefused=false,reconcileRefused=false;try{operation.finishCleanup()}catch{cleanupRefused=true}try{operation.reconcile()}catch{reconcileRefused=true}
    const result={refused,cleanupRefused,reconcileRefused,sameBytesNotIdentity:actualState.identity.fileId===String(actual)&&actualState.digest===digest('old')&&Buffer.concat(chunks).toString()==='old',
      component:actualState.location.component,destinationAbsent:!existsSync(path.join(workspace,'file')),actualPreserved:lstatSync(path.join(state,'runtime','publications','A'.repeat(43),'.old')).ino===actual,captured:readFileSync(path.join(workspace,'.captured'),'utf8')};
    operation.close();root.close();lock.close();console.log(JSON.stringify(result));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { refused: true, cleanupRefused: true, reconcileRefused: true, sameBytesNotIdentity: true,
    component: '.old', destinationAbsent: true, actualPreserved: true, captured: 'old' });
});

test('same-inode same-length last-cut edits remain readable actual preimages without passing expected cleanup', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,lstatSync,openSync,writeSync,closeSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),results=[];
    for(const [index,kind] of ['replace','delete'].entries()){
      const file='file'+index,arenaId=String.fromCharCode(65+index).repeat(43);writeFileSync(path.join(workspace,file),'old',{mode:384});const writer=openSync(path.join(workspace,file),'r+'),original=lstatSync(path.join(workspace,file)).ino;
      const operation=lock.openPublicationOperation(root,{arenaId,kind,path:file,parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},
        desired:kind==='replace'?{kind:'file',mode:420,byteCount:3,digest:digest('new')}:{kind:'absent'},...(kind==='replace'?{stagingName:'.stage'}:{}),quarantineName:'.old'});
      while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();if(kind==='replace')operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
      native.setFault('before_rename',1,()=>{writeSync(writer,Buffer.from('bad'),0,3,0);return 0});operation.commit();operation.revoke();
      let expectedRefused=false;try{while(operation.readPreimageChunk()!==null){}}catch{expectedRefused=true}
      const before=operation.describeActualPreimage();operation.restartRead('actual_preimage');const actual=[];for(let bytes;(bytes=operation.readActualPreimageChunk())!==null;)actual.push(bytes);
      const after=operation.describeActualPreimage();let cleanupRefused=false;try{operation.finishCleanup()}catch{cleanupRefused=true}
      results.push({expectedRefused,cleanupRefused,sameInode:before.identity.fileId===String(original),component:before.location.component,
        actual:Buffer.concat(actual).toString(),digest:after.digest===digest('bad'),retained:readFileSync(path.join(state,'runtime','publications',arenaId,'.old'),'utf8')});
      closeSync(writer);operation.close();
    }root.close();lock.close();console.log(JSON.stringify(results));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), Array.from({ length: 2 }, () => ({ expectedRefused: true, cleanupRefused: true,
    sameInode: true, component: '.old', actual: 'bad', digest: true, retained: 'bad' })));
});

test('a failed actual-preimage consumer restarts without adopting subsequent inode or slot changes', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,renameSync,lstatSync,openSync,writeSync,closeSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    const results=[];for(const [index,change] of ['mutation','slot'].entries()){
      const file='file'+index,arenaId=String.fromCharCode(65+index).repeat(43);writeFileSync(path.join(workspace,file),'old',{mode:384});
      const operation=lock.openPublicationOperation(root,{arenaId,kind:'replace',path:file,parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},
        desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
      while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
      const expected=Buffer.alloc(65537,23);let writer,actual;native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,file),path.join(workspace,file+'.captured'));writeFileSync(path.join(workspace,file),expected,{mode:384});writer=openSync(path.join(workspace,file),'r+');actual=lstatSync(path.join(workspace,file)).ino;return 0});
      try{operation.commit()}catch{}operation.revoke();const first=operation.readActualPreimageChunk();operation.restartRead('actual_preimage');
      const retry=[];for(let bytes;(bytes=operation.readActualPreimageChunk())!==null;)retry.push(bytes);const retried=Buffer.concat(retry).equals(expected);
      operation.restartRead('actual_preimage');operation.readActualPreimageChunk();const slot=path.join(state,'runtime','publications',arenaId,'.stage');
      if(change==='mutation')writeSync(writer,Buffer.from([24]),0,1,65536);else{renameSync(slot,slot+'.saved');writeFileSync(slot,'foreign',{mode:384})}
      let readRefused=false,restartRefused=false,cleanupRefused=false;try{operation.readActualPreimageChunk()}catch{readRefused=true}try{operation.restartRead('actual_preimage')}catch{restartRefused=true}try{operation.finishCleanup()}catch{cleanupRefused=true}
      const preserved=change==='mutation'?lstatSync(slot).ino===actual&&readFileSync(slot)[65536]===24:readFileSync(slot,'utf8')==='foreign'&&lstatSync(slot+'.saved').ino===actual;
      results.push({firstBounded:first.length===65536,retried,readRefused,restartRefused,cleanupRefused,preserved});closeSync(writer);operation.close();
    }root.close();lock.close();console.log(JSON.stringify(results));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), Array.from({ length: 2 }, () => ({ firstBounded: true, retried: true,
    readRefused: true, restartRefused: true, cleanupRefused: true, preserved: true })));
});

test('oversize and multiply linked actual files are observed truthfully but never streamed or cleaned', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,renameSync,lstatSync,truncateSync,linkSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),results=[];
    for(const [index,change] of ['oversize','hardlink'].entries()){
      const file='file'+index,arenaId=String.fromCharCode(65+index).repeat(43);writeFileSync(path.join(workspace,file),'old',{mode:384});
      const operation=lock.openPublicationOperation(root,{arenaId,kind:'delete',path:file,parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'absent'},quarantineName:'.old'});
      while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();while(!operation.finishStage()){}
      let actual;native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,file),path.join(workspace,file+'.captured'));writeFileSync(path.join(workspace,file),'foreign',{mode:384});if(change==='oversize')truncateSync(path.join(workspace,file),268435457);else linkSync(path.join(workspace,file),path.join(workspace,file+'.other'));actual=lstatSync(path.join(workspace,file)).ino;return 0});
      try{operation.commit()}catch{}const observed=operation.describeActualPreimage();let readRefused=false,cleanupRefused=false;try{operation.readActualPreimageChunk()}catch{readRefused=true}try{operation.finishCleanup()}catch{cleanupRefused=true}
      const slot=path.join(state,'runtime','publications',arenaId,'.old');results.push({readRefused,cleanupRefused,kind:observed.kind,byteCount:observed.byteCount,linkCount:observed.linkCount,noDigest:observed.digest===undefined,originalInode:lstatSync(slot).ino===actual,captured:readFileSync(path.join(workspace,file+'.captured'),'utf8')});operation.close();
    }root.close();lock.close();console.log(JSON.stringify(results));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), [
    { readRefused: true, cleanupRefused: true, kind: 'file', byteCount: '268435457', linkCount: 1, noDigest: true, originalInode: true, captured: 'old' },
    { readRefused: true, cleanupRefused: true, kind: 'file', byteCount: '7', linkCount: 2, noDigest: true, originalInode: true, captured: 'old' }
  ]);
});

test('an unexpected symlink preserves raw invalid UTF-8 target bytes without following or normalizing them', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,renameSync,symlinkSync,readlinkSync,lstatSync,readFileSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},
      desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
    const target=Buffer.from([47,255,47,101,204,129]);let actual;native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,'file'),path.join(workspace,'.captured'));symlinkSync(target,path.join(workspace,'file'));actual=lstatSync(path.join(workspace,'file')).ino;return 0});
    let refused=false;try{operation.commit()}catch{refused=true}operation.revoke();const bytes=operation.readActualPreimageChunk(),eof=operation.readActualPreimageChunk(),actualState=operation.describeActualPreimage();
    let cleanupRefused=false;try{operation.finishCleanup()}catch{cleanupRefused=true}
    const slot=path.join(state,'runtime','publications','A'.repeat(43),'.stage');
    const result={refused,cleanupRefused,kind:actualState.kind,raw:bytes.equals(target)&&readlinkSync(slot,{encoding:'buffer'}).equals(target),
      complete:eof===null&&actualState.digest===digest(target)&&actualState.byteCount==='6',originalInode:lstatSync(slot).ino===actual,destination:readFileSync(path.join(workspace,'file'),'utf8')};
    operation.close();root.close();lock.close();console.log(JSON.stringify(result));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { refused: true, cleanupRefused: true, kind: 'symlink', raw: true,
    complete: true, originalInode: true, destination: 'new' });
});

test('unexpected directories expose only real emptiness while unsupported nodes remain physically retained', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';import {createServer} from 'node:net';
    import {writeFileSync,renameSync,mkdirSync,lstatSync,readFileSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),results=[];
    for(const [index,kind] of ['empty','nonempty','socket'].entries()){
      const file='file'+index,arenaId=String.fromCharCode(65+index).repeat(43);writeFileSync(path.join(workspace,file),'old',{mode:384});
      const operation=lock.openPublicationOperation(root,{arenaId,kind:'delete',path:file,parents:[{...root.identity,mode:root.mode}],expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'absent'},quarantineName:'.old'});
      while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();while(!operation.finishStage()){}
      let server;if(kind==='socket'){server=createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(path.join(workspace,'socket'),resolve)})}
      let actual;native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,file),path.join(workspace,file+'.captured'));if(kind==='socket')renameSync(path.join(workspace,'socket'),path.join(workspace,file));else{mkdirSync(path.join(workspace,file),{mode:448});if(kind==='nonempty')writeFileSync(path.join(workspace,file,'child'),'keep')};actual=lstatSync(path.join(workspace,file)).ino;return 0});
      let refused=false;try{operation.commit()}catch{refused=true}let observation;try{observation=operation.describeActualPreimage()}catch{}let readRefused=false,cleanupRefused=false;try{operation.readActualPreimageChunk()}catch{readRefused=true}try{operation.finishCleanup()}catch{cleanupRefused=true}
      const actualPath=path.join(state,'runtime','publications',arenaId,'.old');
      results.push({refused,readRefused,cleanupRefused,observation:observation?{kind:observation.kind,empty:observation.empty,noDigest:observation.digest===undefined}:null,
        retained:lstatSync(actualPath).ino===actual&&(kind==='nonempty'?readFileSync(path.join(actualPath,'child'),'utf8')==='keep':true)});
      operation.close();if(server)await new Promise(resolve=>server.close(resolve));
    }root.close();lock.close();console.log(JSON.stringify(results));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), [
    { refused: true, readRefused: true, cleanupRefused: true, observation: { kind: 'directory', empty: true, noDigest: true }, retained: true },
    { refused: true, readRefused: true, cleanupRefused: true, observation: { kind: 'directory', empty: false, noDigest: true }, retained: true },
    { refused: true, readRefused: true, cleanupRefused: true, observation: null, retained: true }
  ]);
});

test('actual empty-directory data reaches real CAS without granting expected-preimage cleanup', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,renameSync,mkdirSync,lstatSync,readdirSync} from 'node:fs';import path from 'node:path';
    import {preserveActualEmptyPublicationDirectory} from ${JSON.stringify(new URL('./publication-actual-preimage.ts', import.meta.url).href)};
    import {ArtifactCatalog} from ${JSON.stringify(new URL('./artifacts.ts', import.meta.url).href)};
    import {ContentAddressedStore} from ${JSON.stringify(new URL('./cas.ts', import.meta.url).href)};
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'delete',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'absent'},quarantineName:'.old'});
    try {
      while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();while(!operation.finishStage()){}
      let original;native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,'file'),path.join(workspace,'captured'));
        mkdirSync(path.join(workspace,'file'),{mode:448});original=lstatSync(path.join(workspace,'file')).ino;return 0});
      assert.throws(()=>operation.commit());operation.revoke();
      const cas=path.join(state,'cas');mkdirSync(cas,{mode:448});const artifacts=new ArtifactCatalog(new ContentAddressedStore(cas));
      const retained=await preserveActualEmptyPublicationDirectory(artifacts,operation);
      const entries=await artifacts.readCanonical(retained.payload.entriesRef),slot=path.join(state,'runtime','publications','A'.repeat(43),'.old');
      assert.equal(retained.actual.kind,'directory');assert.equal(retained.actual.empty,true);assert.equal(retained.actual.identity.fileId,String(original));
      assert.deepEqual(entries.entries,[]);assert.equal(entries.entryCount,0);assert.equal(entries.byteCount,0);
      assert.equal(retained.metadata.schemaKind,'cliq-workspace-entries-v1');assert.equal(lstatSync(slot).ino,original);assert.deepEqual(readdirSync(slot),[]);
      assert.throws(()=>operation.readActualPreimageChunk());assert.throws(()=>operation.readPreimageChunk());assert.throws(()=>operation.reconcile());assert.throws(()=>operation.finishCleanup());
      console.log(JSON.stringify({preserved:true,cleanupRefused:true,originalRetained:true}));
    } finally {operation.close();root.close();lock.close();}
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { preserved: true, cleanupRefused: true, originalRetained: true });
});

test('actual directory preservation refuses nonempty data and mutations across the real CAS write', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,renameSync,mkdirSync,lstatSync,readdirSync} from 'node:fs';import path from 'node:path';
    import {preserveActualEmptyPublicationDirectory} from ${JSON.stringify(new URL('./publication-actual-preimage.ts', import.meta.url).href)};
    import {ArtifactCatalog} from ${JSON.stringify(new URL('./artifacts.ts', import.meta.url).href)};
    import {ContentAddressedStore} from ${JSON.stringify(new URL('./cas.ts', import.meta.url).href)};
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),results=[];
    try {
      for(const [index,change] of ['nonempty','add-child','replace-slot'].entries()) {
        const name='file'+index,arenaId=String.fromCharCode(65+index).repeat(43);writeFileSync(path.join(workspace,name),'old',{mode:384});
        const operation=lock.openPublicationOperation(root,{arenaId,kind:'delete',path:name,parents:[{...root.identity,mode:root.mode}],
          expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'absent'},quarantineName:'.old'});
        try {
          while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();while(!operation.finishStage()){}
          native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,name),path.join(workspace,name+'.captured'));
            mkdirSync(path.join(workspace,name),{mode:448});if(change==='nonempty')writeFileSync(path.join(workspace,name,'child'),'retain');return 0});
          assert.throws(()=>operation.commit());operation.revoke();
          const slot=path.join(state,'runtime','publications',arenaId,'.old'),original=lstatSync(slot).ino;
          const before=operation.describeActualPreimage();assert.equal(before.empty,change!=='nonempty');
          const cas=path.join(state,'cas'+index);mkdirSync(cas,{mode:448});const artifacts=new ArtifactCatalog(new ContentAddressedStore(cas));
          // The async helper has sampled the actual descriptor before its first
          // real CAS await. No native process is paused or synthetic proof used.
          const retaining=preserveActualEmptyPublicationDirectory(artifacts,operation);
          if(change==='add-child')writeFileSync(path.join(slot,'child'),'retain');
          if(change==='replace-slot'){renameSync(slot,slot+'.saved');mkdirSync(slot,{mode:448})}
          await assert.rejects(retaining);
          assert.throws(()=>operation.readPreimageChunk());assert.throws(()=>operation.reconcile());assert.throws(()=>operation.finishCleanup());
          const originalSlot=change==='replace-slot'?slot+'.saved':slot;
          assert.equal(lstatSync(originalSlot).ino,original);
          if(change==='replace-slot'){assert.notEqual(lstatSync(slot).ino,original);assert.deepEqual(readdirSync(slot),[])}
          else assert.equal(readFileSync(path.join(slot,'child'),'utf8'),'retain');
          results.push({refused:true,cleanupRefused:true,originalRetained:true});
        } finally {operation.close();}
      }
      console.log(JSON.stringify(results));
    } finally {root.close();lock.close();}
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), Array.from({ length: 3 }, () => ({ refused: true, cleanupRefused: true, originalRetained: true })));
});

test('a lost syscall acknowledgment cannot retrospectively capture an unexpected displaced inode by its name', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {writeFileSync,readFileSync,renameSync,lstatSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
    let actual;native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,'file'),path.join(workspace,'.captured'));writeFileSync(path.join(workspace,'file'),'foreign',{mode:384});actual=lstatSync(path.join(workspace,'file')).ino;native.setFault('after_rename',1,()=>5);return 0});
    let commitRefused=false,describeRefused=false,readRefused=false,reconcileRefused=false,retryRefused=false;try{operation.commit()}catch{commitRefused=true}try{operation.describeActualPreimage()}catch{describeRefused=true}try{operation.readActualPreimageChunk()}catch{readRefused=true}try{operation.reconcile()}catch{reconcileRefused=true}try{operation.commit()}catch{retryRefused=true}
    const slot=path.join(state,'runtime','publications','A'.repeat(43),'.stage'),retained=lstatSync(slot).ino===actual&&readFileSync(slot,'utf8')==='foreign';
    operation.close();root.close();lock.close();console.log(JSON.stringify({commitRefused,describeRefused,readRefused,reconcileRefused,retryRefused,retained}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { commitRefused: true, describeRefused: true, readRefused: true,
    reconcileRefused: true, retryRefused: true, retained: true });
});

test('uncertain closure of the separately captured actual preimage descriptor retains the original StateOwner', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';import {writeFileSync,renameSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports,lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace);
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'replace',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest:digest('old')},desired:{kind:'file',mode:420,byteCount:3,digest:digest('new')},stagingName:'.stage',quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();operation.writeChunk(Buffer.from('new'));while(!operation.finishStage()){}
    native.setFault('before_rename',1,()=>{renameSync(path.join(workspace,'file'),path.join(workspace,'.captured'));writeFileSync(path.join(workspace,'file'),'foreign',{mode:384});return 0});try{operation.commit()}catch{}
    const captured=operation.describeActualPreimage().kind==='file';native.setFault('close',3,()=>5);let operationCode,ownerCode,held=false;
    try{operation.close()}catch(error){operationCode=error.code}try{lock.close()}catch(error){ownerCode=error.code}try{native.acquireLock(state,false).close()}catch{held=true}
    console.log(JSON.stringify({captured,operationCode,ownerCode,held}));process.exit(0);
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { captured: true, operationCode: 'ERR_CLIQ_RESOURCE_RETIREMENT',
    ownerCode: 'ERR_CLIQ_RESOURCE_RETIREMENT', held: true });
  const successor = (await loadNativeStateOwner()).acquireLock(state, false); successor.close();
});

// Historical current-path RED: expected outsidePublished:false, observed true
// with refused:true and replacementPreserved:true. The approved captured-object
// contract permits that first effect on the original inode, then requires the
// postcheck to refuse. Restored-identity maintenance is not qualified here.
test('a captured parent moved at the final cut receives only its original effect before the postcheck refuses further release', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    import {mkdirSync,renameSync,writeFileSync,readFileSync,lstatSync,readdirSync,existsSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),digest=createHash('sha256').update('good').digest('hex');
    const module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),parent=path.join(workspace,'dir'),outside=path.join(path.dirname(workspace),'moved-parent');
    mkdirSync(parent,{mode:448});const captured=lstatSync(parent,{bigint:true});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'create',path:'dir/file',parents:[{...root.identity,mode:root.mode},
      {deviceId:String(captured.dev),fileId:String(captured.ino),ownerUid:Number(captured.uid),mode:Number(captured.mode&4095n)}],
      expected:{kind:'absent'},desired:{kind:'file',mode:420,byteCount:4,digest},stagingName:'.stage'});
    operation.arm();operation.stage();operation.writeChunk(Buffer.from('good'));while(!operation.finishStage()){}
    const arena=path.join(state,'runtime','publications','A'.repeat(43)),staged=lstatSync(path.join(arena,'.stage'),{bigint:true});
    let foreignDirectory,foreignFile;
    native.setFault('before_rename',1,()=>{renameSync(parent,outside);mkdirSync(parent,{mode:448});writeFileSync(path.join(parent,'foreign'),'do not alter');
      foreignDirectory=lstatSync(parent,{bigint:true});foreignFile=lstatSync(path.join(parent,'foreign'),{bigint:true});return 0});
    let postcheckCode;try{operation.commit()}catch(error){postcheckCode=error.code}
    // The drift remains unresolved and no durable PathProgress barrier exists.
    // Neither another semantic release nor direct cleanup may continue here.
    const blocked={};for(const [name,method] of [['arm','arm'],['commit','commit'],['cleanup','finishCleanup']]){
      try{operation[method]()}catch(error){blocked[name]=error.code}
    }
    const moved=lstatSync(outside,{bigint:true}),published=lstatSync(path.join(outside,'file'),{bigint:true}),replacement=lstatSync(parent,{bigint:true}),foreign=lstatSync(path.join(parent,'foreign'),{bigint:true});
    const result={postcheckCode,blocked,sameCapturedObject:moved.dev===captured.dev&&moved.ino===captured.ino,
      sameStagedFile:published.dev===staged.dev&&published.ino===staged.ino,publishedBytes:readFileSync(path.join(outside,'file'),'utf8'),
      replacementPreserved:replacement.dev===foreignDirectory.dev&&replacement.ino===foreignDirectory.ino&&foreign.dev===foreignFile.dev&&foreign.ino===foreignFile.ino&&
        readFileSync(path.join(parent,'foreign'),'utf8')==='do not alter'&&readdirSync(parent).length===1,
      arenaRetained:existsSync(arena),noSecondEntry:readdirSync(outside).length===1};
    operation.close();root.close();lock.close();console.log(JSON.stringify(result));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { postcheckCode: 'ERR_CLIQ_STATE_OWNER_NATIVE',
    blocked: { arm: 'ERR_CLIQ_STATE_OWNER_NATIVE', commit: 'ERR_CLIQ_STATE_OWNER_NATIVE', cleanup: 'ERR_CLIQ_STATE_OWNER_NATIVE' },
    sameCapturedObject: true, sameStagedFile: true, publishedBytes: 'good', replacementPreserved: true, arenaRetained: true, noSecondEntry: true });
});

test('an arena rmdir with failed parent fsync never becomes completed by a no-op retry', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),digest=createHash('sha256').update('good').digest('hex');
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'create',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'absent'},desired:{kind:'file',mode:420,byteCount:4,digest},stagingName:'.stage'});
    operation.arm();operation.stage();operation.writeChunk(Buffer.from('good'));while(!operation.finishStage()){}operation.commit();
    while(operation.readDestinationChunk()!==null){}operation.finishCleanup();
    native.setFault('fsync',2,()=>5);let firstFailed=false;try{operation.finishArenaRetirement()}catch{firstFailed=true}
    const firstRetired=operation.observe().arena.retired;
    native.setFault('fsync',1,()=>5);let secondFailed=false;try{operation.finishArenaRetirement()}catch{secondFailed=true}
    const secondRetired=operation.observe().arena.retired;
    native.setFault('none',1,()=>0);operation.finishArenaRetirement();const finalRetired=operation.observe().arena.retired;
    operation.close();root.close();lock.close();console.log(JSON.stringify({firstFailed,firstRetired,secondFailed,secondRetired,finalRetired}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { firstFailed: true, firstRetired: false, secondFailed: true, secondRetired: false, finalRetired: true });
});

test('a lost delete acknowledgment cannot be reinterpreted as unpublished private cleanup', async t => {
  const { binary, state, workspace } = await faultFixture(t);
  const observed = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {Module} from 'node:module';import {createHash} from 'node:crypto';import {writeFileSync,readFileSync} from 'node:fs';import path from 'node:path';
    const [binary,state,workspace]=process.argv.slice(1),module=new Module(binary);process.dlopen(module,binary);const native=module.exports;
    const lock=native.acquireLock(state,true),root=native.openWorkspaceRoot(workspace),digest=createHash('sha256').update('old').digest('hex');
    writeFileSync(path.join(workspace,'file'),'old',{mode:384});
    const operation=lock.openPublicationOperation(root,{arenaId:'A'.repeat(43),kind:'delete',path:'file',parents:[{...root.identity,mode:root.mode}],
      expected:{kind:'file',mode:384,byteCount:3,digest},desired:{kind:'absent'},quarantineName:'.old'});
    while(operation.readOriginalChunk()!==null){}operation.arm();operation.stage();while(!operation.finishStage()){}
    native.setFault('after_rename',1,()=>5);let commitFailed=false;try{operation.commit()}catch{commitFailed=true}operation.revoke();
    let discardRefused=false;try{operation.discardStage()}catch{discardRefused=true}
    const preserved=readFileSync(path.join(state,'runtime','publications','A'.repeat(43),'.old'),'utf8');
    operation.close();root.close();lock.close();console.log(JSON.stringify({commitFailed,discardRefused,preserved}));
  `, binary, state, workspace], { encoding: 'utf8', timeout: 10000 });
  assert.equal(observed.status, 0, observed.stderr);
  assert.deepEqual(JSON.parse(observed.stdout), { commitFailed: true, discardRefused: true, preserved: 'old' });
});
