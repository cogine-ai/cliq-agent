// Exact source-consent data for a human. This grants no execution permission.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeWireRun } from '../kernel/control-wire-data.js';
import { decodeDependencyScriptApprovalWait, decodeDependencyScriptApprovalRequest,
  decodeDependencyScriptApprovalTarget, decodeDependencyScriptPolicyEvidence } from '../kernel/dependency-script-approval.js';
import { parseJsonStrict } from '../kernel/json.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { RunSnapshotV1 } from '../kernel/types.js';
type Reader={artifact(ref:string,options:{maxBytes:number;signal?:AbortSignal}):Promise<Buffer>};
export async function readDependencyScriptWaitingPresentation(app:Reader,snapshot:RunSnapshotV1,value:unknown,signal?:AbortSignal) {
  const wait=decodeDependencyScriptApprovalWait(value),run=decodeWireRun(snapshot.run);
  if(!['agent','delivery'].includes(snapshot.operation)||run.status!=='waiting'||run.waitingReason!=='approval'||run.nextStep!=='verify'||
    canonicalSha256(wait)!==run.waitingOnRef||wait.runId!==run.id||wait.frontierRef!==run.frontierRef||wait.createdFromRevision>=run.revision)
    throw new TypeError('script consent differs from its captured Run');
  const json=async(ref:string)=>{
    signal?.throwIfAborted();const bytes=await app.artifact(ref,{maxBytes:1048576,signal});signal?.throwIfAborted();
    if(sha256Bytes(bytes)!==ref)throw new TypeError('script consent artifact bytes differ');
    const data=parseJsonStrict(new TextDecoder('utf8',{fatal:true,ignoreBOM:true}).decode(bytes));
    if(!canonicalJsonBytes(data).equals(bytes))throw new TypeError('script consent artifact is not canonical');return data;
  };
  const s=wait.subject,e=decodeDependencyScriptPolicyEvidence(await json(s.policyChannelEvidenceRef));
  const q=decodeDependencyScriptApprovalRequest(await json(e.requestRef)),t=decodeDependencyScriptApprovalTarget(await json(s.target));
  const keys=['runId','candidateItemId','candidateOrdinal','sourceCheckpointId','sourceRunSnapshotRef','workspaceStateRef','resultSourceRef',
    'dependencyPlanRef','dependencyPlanDigest','lockfileDigest','scriptConditionsDigest'] as const;
  if(keys.some(k=>s[k]!==q[k]||s[k]!==t[k])||e.runId!==run.id||e.opId!==s.opId||q.opId!==s.opId||e.frontierRef!==wait.frontierRef||q.frontierRef!==wait.frontierRef||
    e.evidenceDigest!==s.policyChannelEvidenceDigest||e.effectiveDisposition==='deny'||e.requestDigest!==q.requestDigest||q.targetRef!==s.target||
    e.targetRef!==s.target||e.targetDigest!==t.targetDigest||q.targetDigest!==t.targetDigest)
    throw new TypeError('script consent substitutes its original source, lock, request or policy');
  return Object.freeze({waitingOnRef:run.waitingOnRef!,text:`Allow package installation scripts for candidate ${s.candidateOrdinal+1}?\n`+
    `Scope: this exact candidate source and lockfile; one dispatched attempt.\nLockfile SHA-256: ${s.lockfileDigest}\n`+
    `Source SHA-256: ${s.resultSourceRef}\nA policy-mode allow does not replace this source-specific consent.`});
}
