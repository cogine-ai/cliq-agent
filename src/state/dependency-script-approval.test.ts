import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes,canonicalSha256 } from '../kernel/canonical.js';
import { prepareDependencyScriptApproval,approveDependencyScripts,readRetainedDependencyScriptsCandidateTemplate,readDependencyScriptDenialCause } from './dependency-script-approval.js';
import { readRetainedControlRoot } from './control-channel.js';
import { assertActiveStateOwner,type StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { createQueuedFixture,disposeFixture,uuidv7 } from './testing/fixtures.js';
import { identityHash } from '../kernel/identity.js';
import { approvalData } from './testing/dependency-script-approval-data.js';
import { publishInProcessChannel } from './store.js';

// Genuine Store/owner/channel/SQLite/CAS. The locked dependency admission is
// deliberately not fabricated; these prove refusal preserves the original Run.
test('ordinary admitted Run cannot mint a candidate consent by caller locators or a retained root context',async()=>{
 const f=await createQueuedFixture('dependency-consent-refusal');
 try {
  const driver=Reflect.get(f.store,'driver') as SqliteDriver,owner=Reflect.get(f.store,'owner') as StateOwnerContext;
  const before=canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId));
  await assert.rejects(prepareDependencyScriptApproval(driver,f.store.artifacts,owner,f.runtimeAuthority,
    {runId:f.runId,expectedRunRevision:f.store.getRun(f.runId).revision}),{code:'STATE_TRANSITION_INVALID'});
  const root=await readRetainedControlRoot(driver,f.store.artifacts);
  assert.throws(()=>assertActiveStateOwner(driver,root as never));
  await assert.rejects(prepareDependencyScriptApproval(driver,f.store.artifacts,root as never,f.runtimeAuthority,
    {runId:f.runId,expectedRunRevision:f.store.getRun(f.runId).revision}));
  assert.deepEqual(canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId)),before);
  await assert.rejects(readDependencyScriptDenialCause(driver,f.store.artifacts,f.runId,{observedAt:f.store.getRun(f.runId).updatedAt}),{code:'STATE_TRANSITION_INVALID'});
  await assert.rejects(readDependencyScriptDenialCause(driver,f.store.artifacts,f.runId,{observedAt:f.store.getRun(f.runId).updatedAt,
    retained:{candidateItemId:'not-a-candidate',sourceCheckpointId:f.store.getRun(f.runId).latestCheckpointId!,
      dependencyPlanRef:canonicalSha256('not a plan'),resultSourceRef:canonicalSha256('not a result')}}));
  assert.deepEqual(canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId)),before);
  assert.equal(driver.prepare("SELECT count(*) n FROM control_requests WHERE method='run.approve'").get<{n:bigint}>()!.n,0n);
  const actual=f.store.getRun(f.runId);
  await assert.rejects(readRetainedDependencyScriptsCandidateTemplate(driver,f.store.artifacts,owner,f.runtimeAuthority,
    {runId:f.runId,candidateItemId:'not-a-candidate',sourceCheckpointId:actual.latestCheckpointId!,dependencyPlanRef:canonicalSha256('not a plan'),resultSourceRef:canonicalSha256('not a result')}));
  assert.deepEqual(canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId)),before);

 }finally{await disposeFixture(f);}
});
test('authenticated public approval cannot create a decision for an unregistered wait and keeps its original error and SQL cut',async()=>{
 const f=await createQueuedFixture('dependency-approve-refusal');
 try {
  const driver=Reflect.get(f.store,'driver') as SqliteDriver,owner=Reflect.get(f.store,'owner') as StateOwnerContext;
  const identity=await publishInProcessChannel(f.store),before=canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId));
  const core={protocolVersion:1 as const,method:'run.approve' as const,requestId:uuidv7(),runId:f.runId,
    expectedRevision:f.store.getRun(f.runId).revision,waitingOnRef:canonicalSha256('unregistered wait'),decision:'allow' as const};
  const request={...core,requestDigest:canonicalSha256(core)};
  await assert.rejects(approveDependencyScripts(driver,f.store.artifacts,owner,f.runtimeAuthority,{request,identity}),{code:'ENOENT'});
  assert.deepEqual(canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId)),before);
  assert.equal(driver.prepare("SELECT count(*) n FROM control_requests WHERE method='run.approve'").get<{n:bigint}>()!.n,0n);
 }finally{await disposeFixture(f);}
});

test('a real authenticated Store refuses script authorization without its actual captured AUTH origin',async()=>{
 const f=await createQueuedFixture('dependency-script-missing-origin');
 try {
  const identity=await publishInProcessChannel(f.store),run=f.store.getRun(f.runId),before=canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId));
  const {t}=approvalData();
  const core={protocolVersion:1 as const,method:'authorization.create' as const,requestId:uuidv7(),decision:{kind:'dependency_install_scripts' as const,purpose:'dependency_install_scripts' as const,
    target:{sessionId:run.sessionId,sourceInspectionId:identityHash('not-an-original-capture'),expectedWorkspaceIdentityDigest:t.workspaceIdentityDigest,conditions:t.conditions}}};
  await assert.rejects(f.store.createAuthorization({...core,requestDigest:canonicalSha256(core)},identity),{code:'RECOVERY_REQUIRED'});
  assert.deepEqual(canonicalJsonBytes(await f.store.readRecoveryClosure(f.runId)),before);
  const driver=Reflect.get(f.store,'driver') as SqliteDriver;
  assert.equal(driver.prepare('SELECT count(*) n FROM authorization_grants').get<{n:bigint}>()!.n,0n);
 }finally{await disposeFixture(f);}
});
