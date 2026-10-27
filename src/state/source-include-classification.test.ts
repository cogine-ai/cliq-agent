// Synthetic immutable data only: no capturing attempt, Run, StateOwner,
// descriptor observation, permission or native retirement proof is created.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readSourceIncludeArtifact } from './source-include-artifacts.js';
import { decodeSourceIncludeClassification, publishSourceIncludeClassification, readSourceIncludeClassification,
  type SourceIncludeClassificationEntry } from './source-include-classification.js';

const input = { principalId:'principal',inspectionId:'inspection',runId:'planned-run',sessionId:'session',
  workspaceIdentityRef:'a'.repeat(64),workspaceIdentityDigest:'b'.repeat(64),selector:{path:'dir',scope:'subtree' as const},
  selectorDigest:canonicalSha256({path:'dir',scope:'subtree'}),admissionIntentDigest:'c'.repeat(64),
  frozenIgnoreRulesRef:'d'.repeat(64),frozenIgnoreRulesDigest:'e'.repeat(64),capturedEntriesRef:'f'.repeat(64),
  capturedTreeDigest:'0'.repeat(64),observedAt:'2026-10-27T00:00:00.000Z' };
const entries = (count:number): SourceIncludeClassificationEntry[] => Array.from({length:count},(_,index)=>({
  path:`dir/${String(index).padStart(6,'0')}`,entryKind:'file',workspaceEntryDigest:canonicalSha256({syntheticOrdinal:index}),
  deviceId:'1',fileId:String(index+1),linkCount:1,classification:'nonignored_in_root'
}));
async function fixture(t: {after(callback:()=>Promise<void>):void}) {
  const root = await mkdtemp(path.join(process.cwd(),'.cliq-include-pages-'));
  await mkdir(path.join(root,'cas'),{mode:0o700});
  t.after(()=>rm(root,{recursive:true,force:true}));
  return {root,artifacts:new ArtifactCatalog(new ContentAddressedStore(path.join(root,'cas')))};
}
const seal = <T extends {evidenceDigest:string}>(value:T) => ({...value,evidenceDigest:digestOmitting(value,'evidenceDigest')});

test('classification pages retain exact full canonical sequence across original JSON boundaries',async t=>{
  const {artifacts}=await fixture(t), members=entries(257);
  const published=await publishSourceIncludeClassification(artifacts,input,members);
  assert.equal(published.evidence.pageRefs.length,3);
  assert.equal(published.evidence.entriesDigest,canonicalSha256(members));
  assert.deepEqual((await readSourceIncludeClassification(artifacts,published.ref)).entries,members);
  for (const ref of published.evidence.pageRefs) {
    const page=await readSourceIncludeArtifact(artifacts,ref,512*1024) as {pageIndex:number;entries:unknown[]};
    assert(page.entries.length<=128);assert(canonicalJsonBytes(page).length<=512*1024);
  }
});

test('full page read rejects missing, reordered, duplicated, substituted and incomplete original closure',async t=>{
  const {artifacts}=await fixture(t), published=await publishSourceIncludeClassification(artifacts,input,entries(257));
  for (const changes of [{pageRefs:[...published.evidence.pageRefs].reverse()},
    {pageRefs:[...published.evidence.pageRefs,'f'.repeat(64)]},
    {pageRefs:[published.evidence.pageRefs[0],...published.evidence.pageRefs]},
    {entryCount:256},{entryCount:258},{entriesDigest:'0'.repeat(64)}]) {
    const value=seal({...published.evidence,...changes});
    const bad=await artifacts.publishCanonical(value,value.format);
    await assert.rejects(readSourceIncludeClassification(artifacts,bad.ref));
  }
  const page=await artifacts.readCanonical<Record<string,unknown>>(published.evidence.pageRefs[0]!);
  const changed={...page,inspectionId:'another-inspection',pageDigest:''};
  changed.pageDigest=digestOmitting(changed,'pageDigest');
  const badPage=await artifacts.publishCanonical(changed,'cliq-source-include-classification-page-v1');
  const root=seal({...published.evidence,pageRefs:[badPage.ref,...published.evidence.pageRefs.slice(1)]});
  const bad=await artifacts.publishCanonical(root,root.format);
  await assert.rejects(readSourceIncludeClassification(artifacts,bad.ref),/binding or ordinal/);
});

test('worst escaped canonical source paths stay in bounded pages without increasing any JSON guard',async t=>{
  const {artifacts}=await fixture(t), prefix=Array.from({length:15},()=> 'a'+'\u0001'.repeat(254)).join('/');
  const members=entries(300).map((entry,index)=>({...entry,
    path:prefix+'/'+String(index).padStart(6,'0')+'\u0001'.repeat(249)}));
  assert(members.every(entry=>Buffer.byteLength(entry.path)===4095));
  assert(members.every(entry=>canonicalJsonBytes(entry).length<32768));
  const published=await publishSourceIncludeClassification(artifacts,{...input,selector:{path:prefix,scope:'subtree'},
    selectorDigest:canonicalSha256({path:prefix,scope:'subtree'})},members);
  assert(published.evidence.pageRefs.length>3);
  assert(canonicalJsonBytes(published.evidence).length<1024*1024);
  assert.deepEqual((await readSourceIncludeClassification(artifacts,published.ref)).entries,members);
  const tooMany=seal({...published.evidence,pageRefs:Array.from({length:10001},(_,index)=>canonicalSha256({index}))});
  assert.throws(()=>decodeSourceIncludeClassification(tooMany),/10000|bound|container/);
});

test('malformed strict JSON, byte overflow and leaf-as-tracked-ancestor cannot become classification data',async t=>{
  const {root,artifacts}=await fixture(t);
  const before=(await readdir(path.join(root,'cas'))).sort();
  await assert.rejects(publishSourceIncludeClassification(artifacts,input,[{...entries(1)[0]!,classification:'tracked_ancestor_in_git_index'}]),
    /not a directory/);
  assert.deepEqual((await readdir(path.join(root,'cas'))).sort(),before);
  for (const bytes of [Buffer.from('{"value":1,"value":2}'),Buffer.from([0xff])]) {
    const raw=await artifacts.publishBytes(bytes,'application/json','cliq-synthetic-json');
    await assert.rejects(readSourceIncludeArtifact(artifacts,raw.ref));
  }
  const overflow=await artifacts.publishBytes(Buffer.alloc(1024*1024+1,32),'application/json','cliq-synthetic-json');
  await assert.rejects(readSourceIncludeArtifact(artifacts,overflow.ref),{code:'ARTIFACT_MISMATCH'});
});

test('cancellation during classification preparation yields before any CAS page publication and preserves its original cause',async t=>{
  const {root,artifacts}=await fixture(t), owner=new AbortController(), cause=new Error('original data preparation cancellation');
  const before=(await readdir(path.join(root,'cas'))).sort();
  const work=publishSourceIncludeClassification(artifacts,input,entries(4096),owner.signal);
  setImmediate(()=>owner.abort(cause));
  await assert.rejects(work,error=>error===cause);
  assert.deepEqual((await readdir(path.join(root,'cas'))).sort(),before);
});
