import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import type { DependencyScriptConditionsV1 } from './dependency.js';
import { decodeDependencyScriptApprovalRequest,decodeDependencyScriptApprovalTarget,decodeDependencyScriptApprovalWait,
 decodeDependencyScriptApprovalDecision,decodeDependencyScriptDecisionItem,decodeDependencyScriptPolicyEvidence,
 dependencyScriptApprovalOpId,dependencyScriptDecisionItemId } from './dependency-script-approval.js';
import { approvalData } from '../state/testing/dependency-script-approval-data.js';
const ref = (name:string) => canonicalSha256({ inertFixture:name });
test('candidate consent keeps exact source, lock, plan and original policy disposition without a grant or template cycle',()=>{
 const {t,q,e,w,d,item}=approvalData();
 for(const [value,decode] of [[t,decodeDependencyScriptApprovalTarget],[q,decodeDependencyScriptApprovalRequest],[e,decodeDependencyScriptPolicyEvidence],[w,decodeDependencyScriptApprovalWait],[d,decodeDependencyScriptApprovalDecision],[item,decodeDependencyScriptDecisionItem]] as const) {
  assert.deepEqual(canonicalJsonBytes(decode(value)),canonicalJsonBytes(value));assert.ok(Object.isFrozen(decode(value)));
  assert.throws(()=>decode({...value,authority:true}));
 }
 assert.equal(e.effectiveDisposition,'allow');assert.equal(w.subject.reason,'source_conditions_changed');
 assert.equal(Object.hasOwn(item,'grantRef'),false);assert.equal(Object.hasOwn(item,'templateRef'),false);
 assert.notEqual(q.dependencyPlanRef,q.dependencyPlanDigest);
});
test('candidate consent rejects same-shaped foreign source and digest aliases, expired decisions and fake dispatch grants',()=>{
 const {t,q,w,d,item}=approvalData();
 const changed={...t,resultSourceRef:ref('other source')};
 assert.throws(()=>decodeDependencyScriptApprovalTarget({...changed,targetDigest:digestOmitting(changed,'targetDigest')}));
 const changedQ={...q,candidateOrdinal:1};assert.throws(()=>decodeDependencyScriptApprovalRequest({...changedQ,requestDigest:digestOmitting(changedQ,'requestDigest')}));
 assert.throws(()=>decodeDependencyScriptApprovalWait({...w,runId:'another Run'}));
 for(const delta of [{grantExpiresAt:d.createdAt},{decision:'deny'},{subjectDigest:ref('other subject')},{waitingSubjectDigest:ref('other wait')}]) {
  const x={...d,...delta};assert.throws(()=>decodeDependencyScriptApprovalDecision({...x,decisionDigest:digestOmitting(x,'decisionDigest')}));
 }
 assert.throws(()=>decodeDependencyScriptDecisionItem({...item,grantRef:ref('foreign grant')}));
 assert.throws(()=>decodeDependencyScriptDecisionItem({...item,templateRef:ref('cycle')}));
});
test('candidate decoders never invoke getters, proxy traps or foreign coercion and keep original JSON limits',()=>{
 const {w}=approvalData();let calls=0;
 const getter={...w};Object.defineProperty(getter,'subject',{enumerable:true,get(){calls++;return w.subject;}});
 const proxy=new Proxy(w,{ownKeys(){calls++;throw Error('trap');},get(){calls++;throw Error('trap');}});
 const foreign=Object.assign(Object.create({toJSON(){calls++;return w;}}),w);
 for(const x of [getter,proxy,foreign])assert.throws(()=>decodeDependencyScriptApprovalWait(x));
 assert.equal(calls,0);
 const deep:Record<string,unknown>={};let at=deep;for(let i=0;i<34;i++){at.n={};at=at.n as Record<string,unknown>;}
 assert.throws(()=>decodeDependencyScriptApprovalWait({...w,extra:deep}));
 const huge={...w,extra:'x'.repeat(1048576)};assert.throws(()=>decodeDependencyScriptApprovalWait(huge));
});
