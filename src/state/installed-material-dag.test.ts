// Real retained CAS bytes/signatures only. No native/Scope/Run/StateOwner
// authority, execution or installed Linux qualification is constructed.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import ts from 'typescript';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { decodeSkillManifest, decodeSkillSourceIdentity } from '../kernel/skill.js';
import { skillInstruction } from './skill-data.js';
import { testFixture } from '../model/testing/fixtures.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';
import { readInstalledRunDataClosures } from './installed-run.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}
async function fixture(t: TestContext) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-material-dag-'));
  await fs.chmod(root, 0o700);t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cas = new ContentAddressedStore(root), authority = await signedVerifierAuthority({ imageByteCount: 4*1024*1024 });
  const artifacts = new ArtifactCatalog(cas, undefined, authority.releaseKeys);
  for (const object of authority.objects) assert.equal(await cas.publish(object.bytes), object.ref);
  const workspace = { schemaVersion: 1, format: 'cliq-workspace-identity-v1', kind: 'live', platform: 'linux',
    ownerPrincipalId: 'inert-data-principal', canonicalRootPath: '/inert-not-an-observed-workspace',
    rootIdentity: { deviceId:'1',fileId:'2',ownerUid:1,mode:448 },identityDigest:'' };
  workspace.identityDigest=digestOmitting(workspace,'identityDigest');
  const workspaceRef=(await artifacts.publishCanonical(workspace,workspace.format)).ref;
  const source={schemaVersion:1,format:'cliq-workspace-instruction-source-v1',workspaceIdentityRef:workspaceRef,
    workspaceIdentityDigest:workspace.identityDigest,entries:[],capturedAt:'2026-10-20T00:00:00.000Z',sourceDigest:''};
  source.sourceDigest=digestOmitting(source,'sourceDigest');
  const sourceRef=(await artifacts.publishCanonical(source,source.format)).ref;
  const instructions={schemaVersion:1,format:'cliq-workspace-instructions-v1',workspaceIdentityDigest:workspace.identityDigest,
    instructionSourceRef:sourceRef,instructionSourceDigest:source.sourceDigest,rendering:'cliq-all-scopes-labeled-instructions-v1',entries:[],manifestDigest:''};
  instructions.manifestDigest=digestOmitting(instructions,'manifestDigest');
  const instructionsRef=(await artifacts.publishCanonical(instructions,instructions.format)).ref;
  const assembly=structuredClone(testFixture().assembly);
  assembly.createdAt='2026-10-20T00:00:01.000Z';assembly.instructions.skills=[];
  assembly.instructions.workspaceInstructionsRef=instructionsRef;
  assembly.instructions.workspaceInstructionsDigest=instructions.manifestDigest;
  assembly.runtime.guestToolchainManifestRef=authority.manifestRef;
  assembly.runtime.guestToolchainManifestDigest=authority.manifest.manifestDigest;
  return {root,cas,artifacts,authority,assembly,instructions,instructionsRef,workspace,workspaceRef};
}

for(const cancel of [false,true]) test(`independent original retained readers overlap real descriptors and join before ${cancel?'cancellation':'return'}`,async t=>{
  const f=await fixture(t), cancellation=new AbortController(), reason=new Error('original data read cancelled');
  const refs=[f.instructionsRef,f.authority.manifestRef], entered=refs.map(gate), release=refs.map(gate);
  const open=fs.open.bind(fs),active=new Set<object>();let peak=0,opened=0,closed=0,settled=false;
  t.mock.method(fs,'open',async(...args:Parameters<typeof open>)=>{
    const handle=await open(...args);active.add(handle);opened++;peak=Math.max(peak,active.size);
    const close=handle.close.bind(handle),index=refs.findIndex(ref=>args[0]===path.join(f.root,ref));
    t.mock.method(handle,'close',async()=>{if(index>=0){entered[index]!.release();await release[index]!.promise;}
      await close();assert(active.delete(handle));closed++;});return handle;
  });
  const pending=readInstalledRunDataClosures(f.artifacts,f.assembly,f.workspace.ownerPrincipalId,f.authority,cancellation.signal);
  void pending.then(()=>{settled=true;},()=>{settled=true;});
  try{
    await Promise.all(entered.map(g=>g.promise));assert.equal(settled,false);assert(active.size>=4);
    if(cancel)cancellation.abort(reason);
    release[0]!.release();await new Promise<void>(resolve=>setImmediate(resolve));assert.equal(settled,false);
    release[1]!.release();
    if(cancel)await assert.rejects(pending,error=>error===reason);
    else {const value=await pending;assert.deepEqual(value.instructions,f.instructions);
      assert.equal(value.retainedToolchain!.manifestRef,f.authority.manifestRef);assert.deepEqual(value.skills,[]);}
    assert.equal(active.size,0);assert.equal(opened,closed);assert(peak<=8,'fixed branches stay below the existing four-leaf/eight-CAS-FD ceiling');
  }finally{release.forEach(g=>g.release());await Promise.allSettled([pending]);assert.equal(active.size,0);assert.equal(opened,closed);}
});

test('a real sibling close failure survives an earlier actual integrity refusal and remains fully joined',async t=>{
  const f=await fixture(t),target=path.join(f.root,f.instructionsRef);
  const bytes=await fs.readFile(target);bytes[0]^=1;await fs.chmod(target,0o600);await fs.writeFile(target,bytes);await fs.chmod(target,0o400);
  const entered=gate(),release=gate(),ordinaryJoined=gate(),open=fs.open.bind(fs),active=new Set<object>();
  const read=f.cas.read.bind(f.cas);
  t.mock.method(f.cas,'read',(...args:Parameters<typeof read>)=>read(...args).catch(error=>{
    if(args[0]===f.instructionsRef)ordinaryJoined.release();throw error;
  }));
  const cause=new Error('actual file close reported retirement failure');let settled=false;
  t.mock.method(fs,'open',async(...args:Parameters<typeof open>)=>{
    const handle=await open(...args);active.add(handle);const close=handle.close.bind(handle);
    t.mock.method(handle,'close',async()=>{if(args[0]===path.join(f.root,f.authority.manifestRef)){entered.release();await release.promise;
      await close();assert(active.delete(handle));throw cause;}await close();assert(active.delete(handle));});return handle;
  });
  const pending=readInstalledRunDataClosures(f.artifacts,f.assembly,f.workspace.ownerPrincipalId,f.authority);
  void pending.then(()=>{settled=true;},()=>{settled=true;});
  try{await Promise.all([entered.promise,ordinaryJoined.promise]);assert.equal(settled,false);
    release.release();await assert.rejects(pending,error=>error instanceof ResourceRetirementError && error.cause===cause);
    assert.equal(active.size,0);
  }finally{release.release();await Promise.allSettled([pending]);assert.equal(active.size,0);}
});

test('a second consumer fully rereads the real large image and rejects its changed bytes, never a cached digest',async t=>{
  const f=await fixture(t),open=fs.open.bind(fs);let imageBytes=0;
  const imagePath=path.join(f.root,f.authority.manifest.guestImageRef);
  t.mock.method(fs,'open',async(...args:Parameters<typeof open>)=>{
    const handle=await open(...args);if(args[0]===imagePath){const read=handle.read.bind(handle);
      t.mock.method(handle,'read',async(...args:Parameters<typeof read>)=>{const result=await read(...args);imageBytes+=result.bytesRead;return result;});}
    return handle;
  });
  await readInstalledRunDataClosures(f.artifacts,f.assembly,f.workspace.ownerPrincipalId,f.authority);
  assert.equal(imageBytes,f.authority.manifest.guestImageByteCount);
  const bytes=await fs.readFile(imagePath);bytes[bytes.length-1]^=1;await fs.chmod(imagePath,0o600);await fs.writeFile(imagePath,bytes);await fs.chmod(imagePath,0o400);
  await assert.rejects(readInstalledRunDataClosures(f.artifacts,f.assembly,f.workspace.ownerPrincipalId,f.authority));
  assert.equal(imageBytes,2*f.authority.manifest.guestImageByteCount);
});

test('pre-cancellation starts no real CAS descriptor',async t=>{
  const f=await fixture(t),abort=new AbortController(),reason=new Error('original before-entry cancellation');abort.abort(reason);
  const open=fs.open.bind(fs);let calls=0;t.mock.method(fs,'open',(...args:Parameters<typeof open>)=>{calls++;return open(...args);});
  await assert.rejects(readInstalledRunDataClosures(f.artifacts,f.assembly,f.workspace.ownerPrincipalId,f.authority,abort.signal),error=>error===reason);
  assert.equal(calls,0);
});

test('source/native DAG keeps every original before/after R and does not move publication, authority or the fixed pool',async()=>{
  // Parse the checked-out implementation only; never execute extracted source
  // or depend on a developer's private baseline. Check the original guarded
  // operations individually so unrelated legitimate borrows cannot mask an R.
  const parse=async(name:string)=>ts.createSourceFile(name,await fs.readFile(new URL(name,import.meta.url),'utf8'),ts.ScriptTarget.Latest,true);
  const [source,current,runtime,catalog]=await Promise.all(['source-target.ts','installed-run.ts','installed-runtime.ts','artifacts.ts'].map(parse));
  function descendants<T extends ts.Node>(root:ts.Node,guard:(node:ts.Node)=>node is T):T[]{
    const found:T[]=[];const visit=(node:ts.Node)=>{if(guard(node))found.push(node);ts.forEachChild(node,visit);};visit(root);return found;
  }
  const text=(node:ts.Node)=>node.getText().replace(/\s+/gu,'');
  const one=<T,>(values:readonly T[],label:string)=>{assert.equal(values.length,1,label);return values[0]!;};
  const calls=(root:ts.Node,name:string)=>descendants(root,ts.isCallExpression).filter(call=>text(call.expression)===name);
  const fn=(file:ts.SourceFile,name:string)=>{const value=one(file.statements.filter((node):node is ts.FunctionDeclaration=>ts.isFunctionDeclaration(node)&&node.name?.text===name),name);assert(value.body);return value.body;};
  const call=(root:ts.Node,name:string)=>one(calls(root,name),name);
  const awaited=(value:ts.CallExpression)=>{assert(ts.isAwaitExpression(value.parent),text(value.expression)+' must remain awaited');return value;};
  const callback=(value:ts.CallExpression)=>{const arrow=value.arguments[1];assert(arrow&&ts.isArrowFunction(arrow)&&ts.isBlock(arrow.body));return arrow.body;};
  const pair=(value:ts.CallExpression)=>{let input=value.arguments[0]!;if(ts.isAsExpression(input))input=input.expression;assert(ts.isArrayLiteralExpression(input));assert.equal(input.elements.length,2);return input;};
  const bracket=(body:ts.Node,operation:ts.Node,signal:string)=>{
    const checks=calls(body,'installed.revalidate');assert.equal(checks.length,2,'this original borrow keeps both explicit R checks');
    checks.forEach(check=>{awaited(check);assert.deepEqual(check.arguments.map(text),[signal]);});
    assert(checks[0]!.end<operation.pos&&operation.end<checks[1]!.pos,'R must remain on both sides of its original operation');
  };

  const sourceBody=fn(source,'createVerifiedSourceInspectionTarget'),sourceJoin=awaited(call(sourceBody,'joinResourceOperations'));
  pair(sourceJoin);const verifier=call(sourceJoin,'readVerifierRequestIdentities');assert.equal(text(verifier.arguments.at(-1)!), 'context.signal');
  const modelBorrow=call(sourceJoin,'withHeldInstalledRuntime'),modelBody=callback(modelBorrow);
  assert.deepEqual([text(modelBorrow.arguments[0]!),text(modelBorrow.arguments[2]!)],['context.selectedRuntime','context.signal']);
  const modelGuard=one(modelBody.statements.filter(ts.isIfStatement),'original selected-model identity guard');
  bracket(modelBody,modelGuard,'context.signal');
  assert(text(modelGuard.expression).includes('installed.bundleDigest!==canonicalSha256(bootstrap.bundle)'));
  assert(text(modelGuard.expression).includes('installed.modelAuthority?.models.some('));
  assert(sourceJoin.end<call(sourceBody,'artifacts.publishCanonicalTriple').pos);
  assert(call(sourceBody,'artifacts.publishCanonicalTriple').end<awaited(call(sourceBody,'recheckVerifiedSourceInspectionTarget')).pos);

  const assembly=fn(current,'assembleInstalledRun'),capture=one(calls(assembly,'withHeldInstalledRuntime').filter(value=>calls(value,'installed.loadStateOwner').length===1),'original capture borrow');
  const captureBody=callback(capture),captureJoin=awaited(call(captureBody,'joinResourceOperations'));
  bracket(captureBody,captureJoin,'signal');pair(captureJoin);
  const retainedSource=call(captureJoin,'readRetainedSourceInspectionTarget');
  assert(ts.isArrowFunction(retainedSource.parent)&&retainedSource.parent.body===retainedSource&&
    retainedSource.parent.modifiers?.some(value=>value.kind===ts.SyntaxKind.AsyncKeyword),'the actual retained read is adopted by its async joined branch');
  assert.deepEqual(call(captureJoin,'installed.loadStateOwner').arguments.map(text),['signal']);
  const loader=one(descendants(runtime,ts.isVariableDeclaration).filter(value=>ts.isIdentifier(value.name)&&value.name.text==='loadSelectedNative'),'original native loader');
  assert(loader.initializer&&ts.isArrowFunction(loader.initializer)&&ts.isBlock(loader.initializer.body));
  const loaderBody=loader.initializer.body,loaderChecks=calls(loaderBody,'checkedRevalidate'),load=awaited(call(loaderBody,'loadHeldStateOwnerImage'));
  assert.equal(loaderChecks.length,2);loaderChecks.forEach(value=>{awaited(value);assert.deepEqual(value.arguments.map(text),['signal']);});
  assert(loaderChecks[0]!.end<load.pos&&load.end<loaderChecks[1]!.pos);

  const ordinary=fn(current,'loadInstalledRunMaterial'),ordinaryBorrow=one(calls(ordinary,'withHeldInstalledRuntime').filter(value=>calls(value,'materialFor').some(read=>text(read.arguments[2]!)==='assembly')),'original ordinary material borrow');
  const ordinaryBody=callback(ordinaryBorrow),ordinaryRead=one(calls(ordinaryBody,'materialFor').filter(value=>text(value.arguments[2]!)==='assembly'),'ordinary full material read');
  bracket(ordinaryBody,awaited(ordinaryRead),'input.signal');
  const freshBorrow=one(calls(assembly,'withHeldInstalledRuntime').filter(value=>calls(value,'publishInstalledModelMaterial').length===1),'original fresh admission borrow'),freshBody=callback(freshBorrow);
  bracket(freshBody,awaited(call(freshBody,'materialFor')),'signal');
  assert.equal(calls(fn(current,'publishInstalledModelMaterial'),'artifacts.publishCanonicalFour').length,1);
  assert(awaited(call(freshBody,'prepareInstalledVerifierAssembly')).end<one(calls(freshBody,'artifacts.publishCanonical').filter(value=>text(value.arguments[0]!)==='policy'),'original policy publication').pos);

  const data=fn(current,'readInstalledRunDataClosures'),skills=awaited(call(data,'readAssemblySkills')),dataJoin=awaited(call(data,'joinResourceOperations'));
  pair(dataJoin);assert(skills.end<dataJoin.pos,'the original nested four-leaf skill pool must join before the independent pair');
  assert.deepEqual(skills.arguments.map(text),['reads','assembly']);
  assert.deepEqual(call(dataJoin,'readInstructions').arguments.map(text),['reads','assembly','principalId']);
  const guest=awaited(call(dataJoin,'readRetainedVerifierToolchain'));
  assert.equal(text(guest.arguments[0]!), 'reads');assert.equal(text(guest.arguments[1]!),'{bundle:runtime.bundle,releaseKeys:runtime.releaseKeys,guestToolchainManifestRef:assembly.runtime.guestToolchainManifestRef,signal}');
  assert.equal(descendants(fn(current,'readInstructions'),ts.isCallExpression).filter(value=>text(value.expression).endsWith('.mapReads')).length,0);
  const map=one(descendants(catalog,ts.isMethodDeclaration).filter(value=>text(value.name)==='mapReads'),'original four-reader catalog method');
  assert.deepEqual(call(map,'Math.min').arguments.map(text),['4','length']);
});


async function addNonemptySkill(f: Awaited<ReturnType<typeof fixture>>) {
  // Retained workspace claims are inert test data, never native observations
  // or source-read permission. All bytes pass the actual closed skill reader.
  const id='bounded-data';
  const raw=[{name:'SKILL.md',bytes:Buffer.from('---\nname: bounded-data\ndescription: Bounded retained data.\n---\nRead [a](a.txt), [b](b.txt), [c](c.txt).\n')},
    ...['a','b','c'].map(name=>({name:name+'.txt',bytes:Buffer.from(name+' retained data\n')}))];
  const rootDescriptor={canonicalRootRelativePath:'.cliq/skills/'+id,deviceId:'1',fileId:'3',ownerUid:1,mode:448 as const};
  const files=raw.map((file,index)=>{
    const fields={canonicalRelativePath:file.name,rawBytesRef:sha256Bytes(file.bytes),rawBytesDigest:sha256Bytes(file.bytes),rawByteCount:file.bytes.length,
      fileDescriptor:{deviceId:'1',fileId:String(index+4),ownerUid:1,mode:420 as const,linkCount:1 as const}};
    return {...fields,sourceEntryDigest:canonicalSha256({sourceScope:'workspace',workspaceIdentityDigest:f.workspace.identityDigest,rootDescriptor,...fields})};
  });
  for(const file of raw)await f.artifacts.publishBytes(file.bytes,'application/octet-stream','cliq-skill-source-file-v1');
  const core={schemaVersion:1,format:'cliq-skill-source-identity-v1',skillId:id,sourceScope:'workspace',workspaceIdentityRef:f.workspaceRef,
    workspaceIdentityDigest:f.workspace.identityDigest,rootDescriptor,files};
  const source=decodeSkillSourceIdentity({...core,sourceIdentityDigest:canonicalSha256(core)});
  const sourceRef=(await f.artifacts.publishCanonical(source,source.format)).ref;
  const text=skillInstruction(id,raw[0]!.bytes),textRef=(await f.artifacts.publishCanonical(text,text.format)).ref;
  const manifestCore={schemaVersion:1,format:'cliq-skill-manifest-v1',skillId:id,sourceScope:'workspace',sourceIdentityRef:sourceRef,
    sourceIdentityDigest:source.sourceIdentityDigest,instructionRef:textRef,instructionDigest:text.textDigest,
    resources:files.slice(1).map(file=>({canonicalRelativePath:file.canonicalRelativePath,kind:'text',contentRef:file.rawBytesRef,contentDigest:file.rawBytesDigest}))};
  const manifest=decodeSkillManifest({...manifestCore,manifestDigest:canonicalSha256(manifestCore)});
  const ref=(await f.artifacts.publishCanonical(manifest,manifest.format)).ref;
  const bundleRef=(await f.artifacts.publishCanonical(f.authority.bundle,'cliq-runtime-bundle-v1')).ref;
  f.assembly.runtime.runtimeBundleRef=bundleRef;f.assembly.runtime.runtimeBundleManifestDigest=f.authority.bundle.manifestDigest;
  f.assembly.instructions.skills=[{skillId:id,manifestRef:ref,manifestDigest:manifest.manifestDigest}];
  f.assembly.assemblyDigest=digestOmitting(f.assembly,'assemblyDigest');
  return {files,manifest};
}

for(const cancelled of [false,true])test(`nonempty skill actual four-leaf CAS pool never overlaps instruction/guest reads: ${cancelled?'cancel':'complete'}`,async t=>{
  const f=await fixture(t),skill=await addNonemptySkill(f),sourceFiles=new Set(skill.files.map(file=>path.join(f.root,file.rawBytesRef)));
  const imagePath=path.join(f.root,f.authority.manifest.guestImageRef),open=fs.open.bind(fs),allOpened=gate(),allClosed=gate();
  const cancellation=new AbortController(),reason=new Error('cancel original nonempty skill read');
  const active=new Set<object>();let skillOpened=0,skillClosed=0,leafActive=0,peakLeaf=0,peakFd=0,settled=false,guestOpened=0;
  t.mock.method(fs,'open',async(...args:Parameters<typeof open>)=>{
    const handle=await open(...args);active.add(handle);peakFd=Math.max(peakFd,active.size);
    const name=String(args[0]),isSkill=sourceFiles.has(name),isImage=name===imagePath;
    const info=await handle.stat(),leaf=info.isFile();if(leaf){leafActive++;peakLeaf=Math.max(peakLeaf,leafActive);}
    if(isSkill && ++skillOpened===4)allOpened.release();
    if(isImage){guestOpened++;const read=handle.read.bind(handle);
      // A real original image descriptor waits for the actual sibling file
      // closes. The old nested DAG therefore exposes its actual fifth leaf;
      // the serial skill stage has already joined when this reader starts.
      t.mock.method(handle,'read',async(...values:Parameters<typeof read>)=>{await allClosed.promise;return read(...values);});}
    const close=handle.close.bind(handle);
    t.mock.method(handle,'close',async()=>{
      if(isSkill)await allOpened.promise;
      await close();assert(active.delete(handle));if(leaf)leafActive--;
      if(isSkill && ++skillClosed===4)allClosed.release();
    });return handle;
  });
  const pending=readInstalledRunDataClosures(f.artifacts,f.assembly,f.workspace.ownerPrincipalId,f.authority,cancellation.signal);
  void pending.then(()=>{settled=true;},()=>{settled=true;});
  try{
    if(cancelled){await allOpened.promise;cancellation.abort(reason);assert.equal(settled,false);}
    if(cancelled)await assert.rejects(pending,error=>error===reason);
    else {const result=await pending;assert.equal(result.skills.length,1);assert.deepEqual(result.skills[0]!.manifest,skill.manifest);}
    assert.equal(active.size,0);assert.equal(leafActive,0);assert.equal(skillOpened,4);assert.equal(skillClosed,4);
    t.diagnostic(JSON.stringify({peakLeaf,peakFd,skillOpened,skillClosed,guestOpened,cancelled}));
    assert(peakLeaf<=4,`actual CAS leaf peak ${peakLeaf} exceeds the original four-reader bound`);
    assert(peakFd<=8,`actual CAS handle peak ${peakFd} exceeds the original eight-handle leaf fixture bound`);
    if(cancelled)assert.equal(guestOpened,0,'cancelled skill stage never starts the later guest reader');
  }finally{allOpened.release();allClosed.release();await Promise.allSettled([pending]);assert.equal(active.size,0);}
});
