// Inert immutable artifacts only. These tests do not create a StateOwner,
// capturing attempt, consumed SQL grant, Run, native proof or live permission.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { SourceIncludeAuthorizationV1 } from '../kernel/source-include.js';
import type { SourceProjectionSpec, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { compileFrozenIgnoreRules } from '../workspace/frozen-ignore.js';
import { ArtifactCatalog } from './artifacts.js';
import { authorizationGrantId, decodeAuthorizationGrant } from './authorization-artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { publishSourceIncludeAuthorizations } from './source-include-capture.js';
import { publishSourceIncludeClassification } from './source-include-classification.js';
import { assertSourceIncludeExpectedDigest } from './source-include-constraints.js';
import { readSourceIncludeProjectionData } from './source-include-projection-data.js';

const createdAt='2026-10-27T00:00:00.000Z', workspaceIdentityDigest='b'.repeat(64);
const common={principalId:'principal',inspectionId:'inspection',runId:'planned-run',sessionId:'session',
  workspaceIdentityRef:'a'.repeat(64),workspaceIdentityDigest,admissionIntentDigest:'c'.repeat(64),createdAt};
function manifest(entries:WorkspaceEntry[]):WorkspaceEntryManifest {
  return {schemaVersion:1,format:'cliq-workspace-entries-v1',entries,entryCount:entries.length,
    byteCount:entries.reduce((sum,entry)=>sum+(entry.kind==='file'?entry.size:entry.kind==='symlink'?Buffer.byteLength(entry.target):0),0),
    treeDigest:canonicalSha256({schemaVersion:1,format:'cliq-workspace-entries-v1',entries})};
}
async function fixture(t:TestContext) {
  const root=await mkdtemp(path.join(process.cwd(),'.cliq-include-constraints-'));
  const cas=path.join(root,'cas');await mkdir(cas,{mode:0o700});t.after(()=>rm(root,{recursive:true,force:true}));
  return {root,cas,artifacts:new ArtifactCatalog(new ContentAddressedStore(cas))};
}
function projection(includes:SourceProjectionSpec['explicitIncludes'],rulesRef:string,rulesDigest:string):SourceProjectionSpec {
  const value:SourceProjectionSpec={schemaVersion:1,matcherVersion:'cliq-exact-path-v1',frozenIgnoreRulesRef:rulesRef,
    frozenIgnoreRulesDigest:rulesDigest,explicitIncludes:includes,explicitExcludes:[],maxChangedPaths:10000,
    maxChangedBytes:1024*1024,projectionDigest:''};value.projectionDigest=digestOmitting(value,'projectionDigest');return value;
}

test('a paged classification reads the complete original 2001-entry source through its original typed contract',async t=>{
  const {artifacts}=await fixture(t),raw=await artifacts.publishBytes(Buffer.alloc(0),'application/octet-stream','cliq-workspace-file-v1');
  const entries=manifest([{path:'dir',kind:'directory',mode:0o755},...Array.from({length:2000},(_,index)=>({
    path:`dir/f${String(index).padStart(6,'0')}`,kind:'file' as const,mode:0o644,size:0,blobRef:raw.ref}))]);
  const captured=await artifacts.publishCanonical(entries,entries.format);
  assert(captured.byteLength<1024*1024);assert.throws(()=>parseJsonStrict(canonicalJsonBytes(entries).toString()),/10000/);
  const rules={schemaVersion:1 as const,format:'cliq-frozen-ignore-rules-v1' as const,matcherVersion:'cliq-git-wildmatch-v1' as const,
    sources:[],rules:[],rulesDigest:''};rules.rulesDigest=digestOmitting(rules,'rulesDigest');
  const rulesRef=(await artifacts.publishCanonical(rules,rules.format)).ref,selector={path:entries.entries[1]!.path,scope:'entry' as const};
  const {createdAt:_createdAt,...classificationIdentity}=common;
  const evidence=await publishSourceIncludeClassification(artifacts,{...classificationIdentity,selector,selectorDigest:canonicalSha256(selector),
    frozenIgnoreRulesRef:rulesRef,frozenIgnoreRulesDigest:rules.rulesDigest,capturedEntriesRef:captured.ref,capturedTreeDigest:entries.treeDigest,
    observedAt:createdAt},[{path:selector.path,entryKind:'file',workspaceEntryDigest:canonicalSha256(entries.entries[1]),
    deviceId:'1',fileId:'2',linkCount:1,classification:'nonignored_in_root'}]);
  const auth:SourceIncludeAuthorizationV1={...common,schemaVersion:1,format:'cliq-source-include-authorization-v1',selector,
    selectorDigest:canonicalSha256(selector),capturedEntriesRef:captured.ref,capturedTreeDigest:entries.treeDigest,kind:'builtin_nonignored',
    frozenIgnoreRulesRef:rulesRef,frozenIgnoreRulesDigest:rules.rulesDigest,classification:'tracked_or_nonignored_in_root',
    classificationEvidenceRef:evidence.ref,classificationEvidenceDigest:evidence.evidence.evidenceDigest,authorizationDigest:''};
  auth.authorizationDigest=digestOmitting(auth,'authorizationDigest');
  const ref=(await artifacts.publishCanonical(auth,auth.format)).ref,p=projection([{...selector,authorizationRef:ref}],rulesRef,rules.rulesDigest);
  assert.equal((await readSourceIncludeProjectionData(artifacts,p,workspaceIdentityDigest,rules)).authorizations.length,1);
  assert.equal((await readSourceIncludeProjectionData(artifacts,p,workspaceIdentityDigest,rules,undefined,entries)).observations[0]?.capturedEntriesRef,captured.ref);
});

async function userData(t:TestContext,expectedDigest?:string) {
  const data=await fixture(t),{artifacts}=data,raw=await artifacts.publishBytes(Buffer.from('original constrained bytes\n'),
    'application/octet-stream','cliq-workspace-file-v1');
  const entries=manifest([{path:'note.txt',kind:'file',mode:0o644,size:raw.byteLength,blobRef:raw.ref}]);
  await artifacts.publishCanonical(entries,entries.format);
  const rules=compileFrozenIgnoreRules([{kind:'gitignore',path:'.gitignore',bytes:Buffer.from('note.txt\n')}],'e'.repeat(64));
  const rulesRef=(await artifacts.publishCanonical(rules,rules.format)).ref;
  const target={kind:'read_scope' as const,purpose:'source' as const,workspaceIdentityDigest,
    canonicalRootRelativePath:'note.txt',scope:'entry' as const,expectedDigest:expectedDigest??raw.ref};
  const sourceRequestId='01900000-0000-7000-8000-000000000001',sourceRequestDigest='d'.repeat(64);
  const core={schemaVersion:1 as const,grantId:authorizationGrantId(common.principalId,sourceRequestId,sourceRequestDigest),
    ownerPrincipalId:common.principalId,channelIdentityRef:'1'.repeat(64),channelIdentityDigest:'2'.repeat(64),sourceRequestId,sourceRequestDigest,
    target,targetDigest:canonicalSha256(target),maxUses:1 as const,createdAt,expiresAt:'2026-10-27T01:00:00.000Z'};
  const receipt={schemaVersion:1 as const,grantId:core.grantId,ownerPrincipalId:core.ownerPrincipalId,targetDigest:core.targetDigest,
    consumer:{kind:'source_inspection' as const,inspectionId:common.inspectionId,admissionIntentDigest:common.admissionIntentDigest},
    consumedAt:createdAt,receiptDigest:''};receipt.receiptDigest=digestOmitting(receipt,'receiptDigest');
  const receiptRef=(await artifacts.publishCanonical(receipt,'cliq-authorization-consumption-receipt-v1')).ref;
  const grant:Extract<AuthorizationGrantV1,{state:'consumed'}>={...core,grantCoreDigest:canonicalSha256(core),rowVersion:2,
    state:'consumed',useCount:1,consumptionReceiptRef:receiptRef,consumedAt:createdAt,rowDigest:''};
  grant.rowDigest=digestOmitting(grant,'rowDigest');decodeAuthorizationGrant(grant);
  const snapshotRef=(await artifacts.publishCanonical(grant,'cliq-authorization-grant-v1')).ref;
  const capture={...common,selectors:[{path:'note.txt',scope:'entry' as const,readGrantId:grant.grantId}],
    scopes:[{grantId:grant.grantId,target,receipt,snapshotRef}]};
  return {...data,raw,entries,rules,rulesRef,target,grant,capture,snapshotRef};
}

test('a matching file constraint retains its complete original consumed snapshot and full bytes',async t=>{
  const data=await userData(t),{artifacts}=data;
  const result=await publishSourceIncludeAuthorizations({...data,observations:new Map()});
  const p=projection(result.includes,data.rulesRef,data.rules.rulesDigest);
  const read=await readSourceIncludeProjectionData(artifacts,p,workspaceIdentityDigest,data.rules);
  const auth=read.authorizations[0]!;assert.equal(auth.kind,'consumed_user_read_grant');
  if(auth.kind!=='consumed_user_read_grant')assert.fail('expected the original data branch');
  assert.equal(auth.consumedGrantSnapshotRef,data.snapshotRef);assert.equal(auth.capturedEntriesRef,canonicalSha256(data.entries));
  const rawPath=path.join(data.cas,data.raw.ref),moved=path.join(data.root,'raw-original');await rename(rawPath,moved);
  try {await assert.rejects(readSourceIncludeProjectionData(artifacts,p,workspaceIdentityDigest,data.rules),{code:'ENOENT'});}
  finally {await rename(moved,rawPath);}
  const snapshotPath=path.join(data.cas,data.snapshotRef),snapshotMoved=path.join(data.root,'snapshot-original');await rename(snapshotPath,snapshotMoved);
  try {await assert.rejects(readSourceIncludeProjectionData(artifacts,p,workspaceIdentityDigest,data.rules),{code:'ENOENT'});}
  finally {await rename(snapshotMoved,snapshotPath);}
  for(const replacement of [{schemaVersion:1,grantId:data.grant.grantId},{...data.grant,consumptionReceiptRef:'0'.repeat(64)}]) {
    const bad=(await artifacts.publishCanonical(replacement,'cliq-authorization-grant-v1')).ref;
    const substituted={...auth,consumedGrantSnapshotRef:bad,authorizationDigest:''};substituted.authorizationDigest=digestOmitting(substituted,'authorizationDigest');
    const ref=(await artifacts.publishCanonical(substituted,auth.format)).ref;
    await assert.rejects(readSourceIncludeProjectionData(artifacts,projection([{...auth.selector,authorizationRef:ref}],data.rulesRef,data.rules.rulesDigest),workspaceIdentityDigest,data.rules));
  }
  assert.equal((await readSourceIncludeProjectionData(artifacts,p,workspaceIdentityDigest,data.rules)).users.length,1);
});

test('mismatched file bytes cannot publish include authorization and retained tampering cannot discard its constraint',async t=>{
  const bad=await userData(t,'0'.repeat(64));
  await assert.rejects(publishSourceIncludeAuthorizations({...bad,observations:new Map()}),{refusalCode:'AUTHORIZATION_REQUIRED'});
  const good=await userData(t),published=await publishSourceIncludeAuthorizations({...good,observations:new Map()});
  const original=(await readSourceIncludeProjectionData(good.artifacts,projection(published.includes,good.rulesRef,good.rules.rulesDigest),workspaceIdentityDigest,good.rules)).authorizations[0]!;
  // A valid replacement manifest cannot change what the original constrained file was.
  const changed=manifest([{path:'note.txt',kind:'file',mode:0o644,size:bad.raw.byteLength,blobRef:'0'.repeat(64)}]);
  const replacement=await good.artifacts.publishCanonical(changed,changed.format);
  const auth={...original,capturedEntriesRef:replacement.ref,capturedTreeDigest:changed.treeDigest,authorizationDigest:''};auth.authorizationDigest=digestOmitting(auth,'authorizationDigest');
  const ref=(await good.artifacts.publishCanonical(auth,auth.format)).ref;
  await assert.rejects(readSourceIncludeProjectionData(good.artifacts,projection([{...auth.selector,authorizationRef:ref}],good.rulesRef,good.rules.rulesDigest),workspaceIdentityDigest,good.rules),{refusalCode:'AUTHORIZATION_REQUIRED'});
});

test('fresh Delivery constraints use actual A kind and complete bytes while B remains immutable',async t=>{
  const data=await userData(t),before=canonicalJsonBytes(data.entries);
  assertSourceIncludeExpectedDigest(data.target,data.entries);
  for(const actual of [manifest([]),manifest([{path:'note.txt',kind:'directory',mode:0o755}]),
    manifest([{path:'note.txt',kind:'symlink',mode:0o777,target:'missing',targetDigest:sha256Bytes(Buffer.from('missing'))}]),
    manifest([{path:'note.txt',kind:'file',mode:0o644,size:0,blobRef:'0'.repeat(64)}])])
    assert.throws(()=>assertSourceIncludeExpectedDigest(data.target,actual),{refusalCode:'AUTHORIZATION_REQUIRED'});
  assert.throws(()=>assertSourceIncludeExpectedDigest({...data.target,scope:'subtree'},data.entries),{refusalCode:'AUTHORIZATION_REQUIRED'});
  const {expectedDigest:_digest,...unconstrained}=data.target;
  assertSourceIncludeExpectedDigest(unconstrained,manifest([]));
  assert(canonicalJsonBytes(data.entries).equals(before));
});
