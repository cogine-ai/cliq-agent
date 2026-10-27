import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes,canonicalSha256 } from '../kernel/canonical.js';
import { readDependencyScriptWaitingPresentation } from './dependency-script-presentation.js';
import { approvalData } from '../state/testing/dependency-script-approval-data.js';
import { createQueuedFixture,disposeFixture } from '../state/testing/fixtures.js';
// Genuine Run shape is only the presentation envelope; the artifacts below
// are inert DTOs, not registered consent or a permissible dependency Run.
test('exact candidate source consent is readable and rejects substituted evidence before displaying it',async()=>{
 const fixture=await createQueuedFixture('dependency-consent-view');
 try {
  const {t,q,e,w}=approvalData();
  const run={...fixture.store.getRun(fixture.runId),id:'run',status:'waiting' as const,nextStep:'verify' as const,waitingReason:'approval' as const,
    waitingOnRef:canonicalSha256(w),frontierRef:w.frontierRef,revision:4};
  const snapshot={schemaVersion:1 as const,operation:'agent' as const,run,latestRunItemSeq:2};
  const data=new Map([t,q,e].map(value=>[canonicalSha256(value),canonicalJsonBytes(value)]));
  const app={async artifact(ref:string){const bytes=data.get(ref);if(!bytes)throw Error('missing');return Buffer.from(bytes);}};
  const view=await readDependencyScriptWaitingPresentation(app,snapshot,w);
  assert.match(view.text,/candidate 1/);assert.match(view.text,new RegExp(w.subject.lockfileDigest));assert.equal(view.waitingOnRef,run.waitingOnRef);
  data.set(canonicalSha256(e),canonicalJsonBytes({...e,principalId:'foreign'}));
  await assert.rejects(readDependencyScriptWaitingPresentation(app,snapshot,w),/artifact bytes differ/);
  data.set(canonicalSha256(e),canonicalJsonBytes(e));
  await assert.rejects(readDependencyScriptWaitingPresentation(app,{...snapshot,run:{...run,frontierRef:canonicalSha256('foreign')}},w),/captured Run/);
  const cancelled=new AbortController();cancelled.abort();
  await assert.rejects(readDependencyScriptWaitingPresentation(app,snapshot,w,cancelled.signal),{name:'AbortError'});
 }finally{await disposeFixture(fixture);}
});
