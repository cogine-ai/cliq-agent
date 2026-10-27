import type { ToolContractManifestV1 } from '../kernel/types.js';
import { readToolRuntimeAuthority } from './tool-runtime-authority.js';
// Exact source-consent on the existing waiting/approval/continuation chain.
// No native launch, acquisition grant, new ledger or mutable policy is created.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { decodeInstalledControlRequest, type RunApproveRequestV1 } from '../kernel/control-wire.js';
import { decodeWireRun, assertControlWireJson, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { decodeDependencyInstallScriptsTemplate, type DependencyInstallScriptsAuthorizationTemplateV1 } from '../kernel/dependency.js';
import { decodeDependencyRequest, decodeDependencyTarget } from '../kernel/dependency-invocation.js';
import { decodeDependencyScriptApprovalRequest, decodeDependencyScriptApprovalTarget, decodeDependencyScriptPolicyEvidence,
  decodeDependencyScriptApprovalWait, decodeDependencyScriptApprovalDecision, decodeDependencyScriptDecisionItem,
  dependencyScriptApprovalOpId, dependencyScriptWaitCheckpointId, dependencyScriptDecisionCheckpointId, dependencyScriptDecisionItemId,
  type DependencyScriptApprovalBinding, type DependencyScriptApprovalRequest, type DependencyScriptApprovalTarget,
  type DependencyScriptPolicyEvidence, type DependencyScriptApprovalWait, type DependencyScriptApprovalDecision, type DependencyScriptDecisionItem } from '../kernel/dependency-script-approval.js';
import { addCanonicalDuration, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { Run, RunFrontier, ContinuationItem } from '../kernel/types.js';
import type { PolicyEngineProfileV1, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { assertRunPolicySnapshot, evaluateFrozenPolicyKey } from '../policy/tool-policy.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import { type ArtifactCatalog, type PublishedArtifact, insertArtifactMetadata } from './artifacts.js';
import type { AuthorizationRuntime } from './authorization.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { assertChildAncestryRelease } from './child-ancestry.js';
import { assertCurrentControlFrame, readHistoricalControlChannel, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest } from './decoders.js';
import { readCurrentDependencyCandidate, readRetainedDependencyCandidate, type DependencyCandidateData } from './dependency-candidate.js';
import { readDependencyScriptsTemplateHistory } from './dependency-script-history.js';
import { sameDependencyScriptInputs } from './dependency-script-source.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { readInvocationJournal } from './repositories/journal.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { insertControlRequest, readCheckpoint, readControlRequest, readRun, readSessionPrincipalId } from './rows.js';
import { validateHistoricalSourceRunCounters } from './source-run-counters.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

const same=(a:unknown,b:unknown)=>canonicalJsonBytes(a).equals(canonicalJsonBytes(b));
function invalid(message:string):never {throw new KernelStorageError('RECOVERY_REQUIRED','dependency script approval '+message);}
const immutableRun=(r:Run)=>({id:r.id,sessionId:r.sessionId,parentRunId:r.parentRunId??null,specRef:r.specRef,createdAt:r.createdAt,deadlineAt:r.deadlineAt});
function originalBinding(source:DependencyCandidateData, snapshotRef:string):DependencyScriptApprovalBinding {
  return {runId:source.run.id,candidateItemId:source.candidate.itemId,candidateOrdinal:source.candidateOrdinal,
    sourceCheckpointId:source.checkpoint.id,sourceRunSnapshotRef:snapshotRef,workspaceStateRef:source.checkpoint.workspaceStateRef,
    resultSourceRef:source.candidate.resultSourceRef,dependencyPlanRef:source.dependencyPlanRef,dependencyPlanDigest:source.plan.planDigest,
    lockfileDigest:source.plan.lockfileDigest,scriptConditionsDigest:canonicalSha256(source.conditions)};
}
function frontierFor(source:DependencyCandidateData):RunFrontier {
  return {schemaVersion:1,kind:'verify',phase:'dependencies',candidateItemId:source.candidate.itemId,resultSourceRef:source.candidate.resultSourceRef,
    verifierPlanRef:source.verifierPlanRef,dependencyPlanRef:source.dependencyPlanRef,nextVerifierIndex:0,
    afterPass:source.spec.operation==='agent'?'finalize':'delivery_approval'};
}
function targetFor(source:DependencyCandidateData,binding:DependencyScriptApprovalBinding):DependencyScriptApprovalTarget {
  const supervisors=source.bundle.entries.filter(e=>e.role==='supervisor');
  if(supervisors.length!==1||!supervisors[0]!.executable)invalid('has no unique original signed Supervisor');const e=supervisors[0]!;
  const v={...binding,schemaVersion:1 as const,format:'cliq-dependency-script-approval-target-v1' as const,
    workspaceIdentityRef:source.session.workspaceIdentityRef,workspaceIdentityDigest:source.workspaceIdentity.identityDigest,
    conditions:source.conditions,execution:{kind:'supervisor_operation' as const,handlerId:'dependency_install_scripts_approval' as const,
      supervisorEntryId:e.entryId,supervisorEntryVersion:e.version,supervisorExecutableDigest:e.digest}};
  return decodeDependencyScriptApprovalTarget({...v,targetDigest:canonicalSha256(v)});
}
function requestFor(source:DependencyCandidateData,binding:DependencyScriptApprovalBinding,target:DependencyScriptApprovalTarget,frontierRef:string) {
  const v={...binding,schemaVersion:1 as const,format:'cliq-dependency-script-approval-request-v1' as const,
    opId:dependencyScriptApprovalOpId(binding),assemblyRef:source.spec.assemblyRef,frontierRef,targetRef:canonicalSha256(target),targetDigest:target.targetDigest};
  return decodeDependencyScriptApprovalRequest({...v,requestDigest:canonicalSha256(v)});
}
function policyFor(source:DependencyCandidateData,policy:RunPolicySnapshotV1,request:DependencyScriptApprovalRequest,target:DependencyScriptApprovalTarget,at:string) {
  assertRunPolicySnapshot({policy,policyRef:source.spec.policyRef,assembly:source.assembly,principalId:source.principalId,
    workspaceIdentityDigest:source.workspaceIdentity.identityDigest});
  if(at<policy.createdAt)invalid('predates its frozen policy');
  const key='dependency_install_scripts/'+source.plan.lockfileDigest;
  const evaluated=evaluateFrozenPolicyKey(policy,'dependency_install_scripts','named-action',key);
  const v={schemaVersion:1 as const,format:'cliq-policy-channel-evidence-v1' as const,principalId:source.principalId,runId:source.run.id,
    policyRef:source.spec.policyRef,policyDigest:policy.policyDigest,frontierRef:request.frontierRef,opId:request.opId,
    requestRef:canonicalSha256(request),requestDigest:request.requestDigest,targetRef:request.targetRef,targetDigest:target.targetDigest,
    actionClass:'dependency_install_scripts' as const,channel:'named-action' as const,identityKey:key,
    decisionSource:evaluated.ruleId?'rule' as const:'mode_fallthrough' as const,matchedRuleIds:evaluated.ruleId?[evaluated.ruleId]:[],
    effectiveDisposition:evaluated.disposition,evaluatedAt:at};return decodeDependencyScriptPolicyEvidence({...v,evidenceDigest:canonicalSha256(v)});
}
async function publish(artifacts:ArtifactCatalog,plans:readonly PlannedArtifact[]) {
  const out:PublishedArtifact[]=[];
  for(let i=0;i<plans.length;i+=4)out.push(...await joinResourceOperations(plans.slice(i,i+4).map(async plan=>{
    const value=await artifacts.publishBytes(plan.bytes,plan.mediaType,plan.schemaKind);
    requireEqual(value,{ref:plan.ref,byteLength:plan.bytes.length,mediaType:plan.mediaType,schemaKind:plan.schemaKind},'exact durable script approval');return value;
  })));
  return out;
}
async function material(driver:SqliteDriver,artifacts:ArtifactCatalog,runtime:AuthorizationRuntime,runId:string,requestRef:string) {
  const request=decodeDependencyScriptApprovalRequest(await readCanonicalArtifact(artifacts,requestRef));if(request.runId!==runId)invalid('request belongs to another Run');
  const source=await readRetainedDependencyCandidate(driver,artifacts,runId,{candidateItemId:request.candidateItemId,sourceCheckpointId:request.sourceCheckpointId,
    dependencyPlanRef:request.dependencyPlanRef,resultSourceRef:request.resultSourceRef,releaseKeys:runtime.releaseKeys});
  const decodedItems=new Map(await artifacts.mapReads(source.items, async row => [row.itemId, await readCanonicalArtifact<ContinuationItem>(artifacts,row.payloadRef)] as const));
  const original=decodeWireRun(await readCanonicalArtifact(artifacts,request.sourceRunSnapshotRef));const cp=source.checkpoint;
  requireEqual(immutableRun(original),immutableRun(source.run),'script approval immutable original Run');
  if(original.latestCheckpointId!==cp.id||original.revision!==cp.basedOnRunRevision+1||original.updatedAt!==cp.createdAt||original.status!=='queued'||
    original.nextStep!=='verify'||original.activeWorkerLaunchId||original.waitingReason||original.waitingOnRef||original.stopIntentRef||original.cancelRequested||
    original.parentCancellationRef||original.resultRef||original.terminalReason||original.terminalDetailRef)invalid('snapshot is not its original worker-free source');
  const frontier=frontierFor(source);requireEqual(await readCanonicalArtifact(artifacts,request.frontierRef),frontier,'script original dependency frontier');
  if(original.frontierRef!==request.frontierRef)invalid('snapshot has another frontier');
  await validateHistoricalSourceRunCounters(driver,artifacts,{original,checkpoint:cp,journal:source.journal,workers:source.workers,
    items:source.items.map(row=>({itemSeq:row.itemSeq,item:decodedItems.get(row.itemId)!}))});
  const binding=originalBinding(source,request.sourceRunSnapshotRef),target=targetFor(source,binding);
  requireEqual(request,requestFor(source,binding,target,request.frontierRef),'script complete source request');
  requireEqual(await readCanonicalArtifact(artifacts,request.targetRef),target,'script complete source target');
  const policy=await readPolicyData(artifacts,source,runtime);
  if(source.policy.installScriptsPolicy!=='exact_lockfile_grant'||!source.plan.allowInstallScripts||!source.policy.installScriptsGrantRef)invalid('cannot expand a frozen scriptless policy');
  const {readDependencyScriptsTemplateHistoryData}=await import('./dependency-script-history.js');
  const initial=await readDependencyScriptsTemplateHistoryData(driver,artifacts,runtime,{runId,templateRef:source.policy.installScriptsGrantRef});
  if(initial.template.provenance.kind!=='run_admission')invalid('candidate consent lacks its complete original admission consent');
  initial.assertUnchanged(driver);source.assertUnchanged(driver);return {source,original,request,target,policy,frontier,decodedItems};
}
function waitingFor(m:Pick<Awaited<ReturnType<typeof material>>,'source'|'original'|'request'>,evidence:DependencyScriptPolicyEvidence):DependencyScriptApprovalWait {
  const b=originalBinding(m.source,m.request.sourceRunSnapshotRef);
  return decodeDependencyScriptApprovalWait({schemaVersion:1,kind:'approval',runId:m.source.run.id,createdFromRevision:m.original.revision,
    createdAt:evidence.evaluatedAt,frontierRef:m.request.frontierRef,subject:{...b,kind:'dependency_install_scripts',reason:'source_conditions_changed',
      opId:m.request.opId,target:m.request.targetRef,policyChannelEvidenceRef:canonicalSha256(evidence),policyChannelEvidenceDigest:evidence.evidenceDigest}});
}
export function assertDependencyScriptWaitingRun(original:Run,current:Run):void {
  decodeWireRun(original);decodeWireRun(current);if(same(original,current))return;
  if(original.status!=='waiting'||original.waitingReason!=='approval'||original.stopIntentRef||original.cancelRequested||
    !current.stopIntentRef||current.revision<=original.revision||current.updatedAt<original.updatedAt)invalid('waiting Run changed without its additive Stop');
  const stable=({revision:_r,updatedAt:_u,stopIntentRef:_s,cancelRequested:_c,parentCancellationRef:_p,...rest}:Run)=>rest;
  requireEqual(stable(current),stable(original),'script stopped wait retains its original source');
}
export async function readDependencyScriptApprovalWait(driver:SqliteDriver,artifacts:ArtifactCatalog,runtime:AuthorizationRuntime,runId:string,waitRef:string) {
  const wait=decodeDependencyScriptApprovalWait(await readCanonicalArtifact(artifacts,waitRef));if(wait.runId!==runId)invalid('wait has another Run');
  const s=wait.subject,target=decodeDependencyScriptApprovalTarget(await readCanonicalArtifact(artifacts,s.target));
  const source=await readRetainedDependencyCandidate(driver,artifacts,runId,{candidateItemId:s.candidateItemId,sourceCheckpointId:s.sourceCheckpointId,
    dependencyPlanRef:s.dependencyPlanRef,resultSourceRef:s.resultSourceRef,releaseKeys:runtime.releaseKeys});
  const request=requestFor(source,originalBinding(source,s.sourceRunSnapshotRef),target,wait.frontierRef);
  const m=await material(driver,artifacts,runtime,runId,canonicalSha256(request));
  const evidence=decodeDependencyScriptPolicyEvidence(await readCanonicalArtifact(artifacts,s.policyChannelEvidenceRef));
  requireEqual(evidence,policyFor(m.source,m.policy,m.request,m.target,wait.createdAt),'script exact original policy evidence');
  if(evidence.effectiveDisposition==='deny')invalid('denied policy cannot create consent wait');
  requireEqual(wait,waitingFor(m,evidence),'script exact source-bound wait');
  const checkpoint=readCheckpoint(driver,dependencyScriptWaitCheckpointId(waitRef)),cp=m.source.checkpoint;
  if(checkpoint.runId!==runId||checkpoint.basedOnRunRevision!==m.original.revision||checkpoint.createdAt!==wait.createdAt||checkpoint.reason!=='auto'||
    checkpoint.runItemSeq!==cp.runItemSeq||checkpoint.journalSeq!==cp.journalSeq||checkpoint.workspaceStateRef!==cp.workspaceStateRef||checkpoint.contextManifestRef!==cp.contextManifestRef)
    invalid('wait has no original atomic Checkpoint');
  const waitingRun:Run={...m.original,status:'waiting',waitingReason:'approval',waitingOnRef:waitRef,latestCheckpointId:checkpoint.id,
    revision:m.original.revision+1,updatedAt:wait.createdAt};
  return {...m,wait,evidence,checkpoint,waitingRun};
}
function decisionItem(m:Awaited<ReturnType<typeof readDependencyScriptApprovalWait>>,d:DependencyScriptApprovalDecision):DependencyScriptDecisionItem {
  const ref=canonicalSha256(d);return decodeDependencyScriptDecisionItem({schemaVersion:1,kind:'policy_decision',subjectKind:'dependency_install_scripts',
    itemId:dependencyScriptDecisionItemId(d.runId,ref),runId:d.runId,opId:m.request.opId,principalId:d.principalId,decisionSource:'interactive_approval',
    waitingSubjectRef:d.waitingSubjectRef,decisionRef:ref,policyChannelEvidenceRef:canonicalSha256(m.evidence),policyChannelEvidenceDigest:m.evidence.evidenceDigest,
    decision:d.decision,createdAt:d.createdAt});
}
function templateFor(m:Awaited<ReturnType<typeof readDependencyScriptApprovalWait>>,d:DependencyScriptApprovalDecision,responseRef:string) {
  if(d.decision!=='allow'||!d.grantExpiresAt) return undefined;
  const s=m.source,p=s.plan,c=s.conditions;
  const v:DependencyInstallScriptsAuthorizationTemplateV1={schemaVersion:1,format:'cliq-dependency-install-scripts-authorization-v1',runId:s.run.id,
    ownerPrincipalId:s.principalId,workspaceIdentityDigest:s.workspaceIdentity.identityDigest,
    provenance:{kind:'candidate_approval',waitingSubjectRef:d.waitingSubjectRef,decisionRef:canonicalSha256(d),responseRef,requestId:d.requestId,requestDigest:d.requestDigest,
      candidateOrdinal:s.candidateOrdinal,dependencyPlanRef:s.dependencyPlanRef,resultSourceRef:s.candidate.resultSourceRef},
    scriptConditions:c,guestToolchainManifestRef:p.guestToolchainManifestRef,allowedAdapters:[...s.policy.allowedAdapters],lockfilePath:p.lockfilePath,
    lockfileRef:p.lockfileRef,lockfileDigest:p.lockfileDigest,packageManifestRef:p.packageManifest.contentRef,packageManifestDigest:p.packageManifest.contentDigest,
    bindingGyp:p.bindingGyp,registryTargetsDigest:c.execution.registryTargetsDigest,maxCandidateGenerations:s.spec.budgets.repairAttempts+1,
    maxDispatchedAttemptsPerPlan:1,expiresAt:d.grantExpiresAt,templateDigest:''};v.templateDigest=canonicalSha256(Object.fromEntries(Object.entries(v).filter(([k])=>k!=='templateDigest')));
  return decodeDependencyInstallScriptsTemplate(v);
}
function validateDecision(m:Awaited<ReturnType<typeof readDependencyScriptApprovalWait>>,d:DependencyScriptApprovalDecision) {
  const expiry=addCanonicalDuration(d.createdAt,Math.min(d.requestedTtlMs??3600000,parseCanonicalTime(m.original.deadlineAt)-parseCanonicalTime(d.createdAt)));
  if(d.runId!==m.source.run.id||d.principalId!==m.source.principalId||d.waitingSubjectRef!==canonicalSha256(m.wait)||
    d.expectedRunRevision!==m.wait.createdFromRevision+1||d.frontierRef!==m.request.frontierRef||!same(d.subject,m.wait.subject)||
    d.createdAt<m.wait.createdAt||d.createdAt>=m.original.deadlineAt||d.decision==='allow'&&d.grantExpiresAt!==expiry||
    d.decisionId!==identityHash(d.principalId,d.runId,d.waitingSubjectRef,d.requestId,d.requestDigest))invalid('decision has another original subject, identity or lifetime');
}
export async function readDependencyScriptApproval(driver:SqliteDriver,artifacts:ArtifactCatalog,runtime:AuthorizationRuntime,runId:string,decisionRef:string) {
  const d=decodeDependencyScriptApprovalDecision(await readCanonicalArtifact(artifacts,decisionRef));
  const m=await readDependencyScriptApprovalWait(driver,artifacts,runtime,runId,d.waitingSubjectRef);validateDecision(m,d);
  const control=readControlRequest(driver,d.principalId,'run.approve',d.requestId),limit=d.grantExpiresAt??m.original.deadlineAt;
  if(!control||control.requestDigest!==d.requestDigest||control.channelIdentityRef!==d.channelIdentityRef||control.channelIdentityDigest!==d.channelIdentityDigest||
    control.committedAt<d.createdAt||control.committedAt>=limit||!readTimeFence(driver)||control.committedAt>readTimeFence(driver)!.lastAcceptedAt)
    invalid('has no original authenticated registration within its lifetime');
  const request=decodeInstalledControlRequest({...await readCanonicalArtifact<Record<string,unknown>>(artifacts,control.requestDigest),requestDigest:control.requestDigest});
  requireEqual(request,{protocolVersion:1,method:'run.approve',requestId:d.requestId,requestDigest:d.requestDigest,runId,expectedRevision:d.expectedRunRevision,
    waitingOnRef:d.waitingSubjectRef,decision:d.decision,...(d.requestedTtlMs===undefined?{}:{ttlMs:d.requestedTtlMs})},'script original approval request');
  const {channel}=await readHistoricalControlChannel(driver,artifacts,d);
  const history=await readRetainedStateOwnerHistory(driver,artifacts,d.stateOwnerEpoch),owner=history.entries.at(-1)!.owner;
  if(owner.ownerEpoch!==d.stateOwnerEpoch||owner.supervisorInstanceId!==d.supervisorInstanceId||owner.acquiredAt>d.createdAt||
    owner.state==='terminal'&&owner.releasedAt<control.committedAt||channel.openedAt>d.createdAt)invalid('escaped its original owner/channel');
  await readSupervisorInspector(artifacts,owner,m.source.assembly,{...d,observedAt:control.committedAt});
  const item=decisionItem(m,d),rows=m.source.items.filter(row=>row.itemId===item.itemId);
  if(rows.length!==1||rows[0]!.payloadRef!==canonicalSha256(item))invalid('has no unique original consent item');
  requireEqual(await readCanonicalArtifact(artifacts,rows[0]!.payloadRef),item,'script registered consent item');
  const checkpoint=readCheckpoint(driver,dependencyScriptDecisionCheckpointId(decisionRef));
  if(checkpoint.runId!==runId||checkpoint.reason!=='auto'||checkpoint.basedOnRunRevision!==d.expectedRunRevision||checkpoint.createdAt!==d.createdAt||
    checkpoint.workspaceStateRef!==m.checkpoint.workspaceStateRef||checkpoint.journalSeq!==m.checkpoint.journalSeq||
    checkpoint.runItemSeq!==m.checkpoint.runItemSeq+1||rows[0]!.itemSeq!==checkpoint.runItemSeq)invalid('has no exact atomic decision Checkpoint');
  const context=decodeContextManifest(await readCanonicalArtifact(artifacts,checkpoint.contextManifestRef));
  validateContextItems(context,m.source.items.slice(0,checkpoint.runItemSeq).map(row=>({itemSeq:row.itemSeq,itemRef:row.payloadRef,item:m.decodedItems.get(row.itemId)!})));
  const next:Run={...m.original,revision:d.expectedRunRevision+1,latestCheckpointId:checkpoint.id,updatedAt:d.createdAt};
  const response={protocolVersion:1 as const,ok:true as const,result:{method:'run.approve' as const,decisionRef,
    snapshot:{schemaVersion:1 as const,operation:m.source.spec.operation,run:next,latestRunItemSeq:checkpoint.runItemSeq}}};
  requireEqual(await readCanonicalArtifact(artifacts,control.responseRef),response,'script exact original first response');
  const template=templateFor(m,d,control.responseRef),templateRef=template&&canonicalSha256(template);
  if(template)requireEqual(await readCanonicalArtifact(artifacts,templateRef!),template,'script complete registered template');
  function assertUnchanged(connection:SqliteConnection|SqliteDriver) {
    m.source.assertUnchanged(connection);history.assertUnchanged(connection);
    requireEqual(readControlRequest(connection,d.principalId,'run.approve',d.requestId),control,'script original approval registration');
    requireEqual(readCheckpoint(connection,m.checkpoint.id),m.checkpoint,'script wait checkpoint');
    requireEqual(readCheckpoint(connection,checkpoint.id),checkpoint,'script original decision checkpoint');
  }
  assertUnchanged(driver);return {...m,decision:d,item,control,response,template,templateRef,assertUnchanged};
}
async function decisions(driver:SqliteDriver,artifacts:ArtifactCatalog,runtime:AuthorizationRuntime,source:DependencyCandidateData) {
  const out:Array<Awaited<ReturnType<typeof readDependencyScriptApproval>>>=[];
  for(const row of source.items) {
    const value=await readCanonicalArtifact<ContinuationItem>(artifacts,row.payloadRef);
    if(value?.kind!=='policy_decision'||value.subjectKind!=='dependency_install_scripts')continue;
    const item=decodeDependencyScriptDecisionItem(value);
    const original=await readDependencyScriptApproval(driver,artifacts,runtime,source.run.id,item.decisionRef);
    requireEqual(original.item,item,'script candidate registered history item');
    if(original.source.candidate.itemId===source.candidate.itemId&&original.source.dependencyPlanRef===source.dependencyPlanRef&&
      original.source.candidate.resultSourceRef===source.candidate.resultSourceRef)out.push(original);
  }
  if(out.some((v,i)=>v.decision.decision==='deny'&&i!==out.length-1))invalid('a sticky denied candidate was approved again');
  return out;
}
async function alreadyClaimed(artifacts:ArtifactCatalog,source:DependencyCandidateData) {
  for(const row of source.journal) {
    if(row.opKind!=='tool'||row.phase!=='dispatch_claimed')continue;
    const raw=await readCanonicalArtifact<Record<string,unknown>>(artifacts,row.requestRef);
    if(raw.format!=='cliq-dependency-request-v1')continue;
    const request=decodeDependencyRequest(raw),target=decodeDependencyTarget(await readCanonicalArtifact(artifacts,request.targetRef));
    if(request.candidateItemId===source.candidate.itemId&&request.dependencyPlanRef===source.dependencyPlanRef&&target.resultSourceRef===source.candidate.resultSourceRef)return true;
  }
  return false;
}
/** The core supplies only immutable locators; committed decision data, never a
 * caller's template/allow boolean, chooses a candidate-specific template. */
export async function readDependencyScriptsCandidateTemplate(driver:SqliteDriver,artifacts:ArtifactCatalog,owner:StateOwnerContext,runtime:AuthorizationRuntime,
  input:{runId:string;candidateItemId:string;dependencyPlanRef:string;resultSourceRef:string},signal?:AbortSignal) {
  assertActiveStateOwner(driver,owner);const reads=signal?artifacts.withReadSignal(signal):artifacts;
  const source=await readCurrentDependencyCandidate(driver,reads,input.runId,{releaseKeys:runtime.releaseKeys,signal});
  if(source.candidate.itemId!==input.candidateItemId||source.dependencyPlanRef!==input.dependencyPlanRef||source.candidate.resultSourceRef!==input.resultSourceRef)
    invalid('template locator differs from the actual dependency frontier');
  return selectRegisteredCandidateTemplate(driver,reads,owner,runtime,source);
}
async function selectRegisteredCandidateTemplate(driver:SqliteDriver,reads:ArtifactCatalog,owner:StateOwnerContext,
  runtime:AuthorizationRuntime,source:DependencyCandidateData) {
  const found=await decisions(driver,reads,runtime,source),last=found.at(-1);
  reads.assertReadActive();source.assertUnchanged(driver);assertActiveStateOwner(driver,owner);
  return last?.decision.decision==='allow'?Object.freeze({template:last.template!,templateRef:last.templateRef!,assertUnchanged:last.assertUnchanged}):undefined;
}
/** Active preparation/release may read a committed consent after the parent
 * worker activates. Only its original registered request supplies this exact
 * source Checkpoint; no current-state fallback, wait or new permission exists.
 * The initial admission template still has its own complete history reader. */
export async function readRetainedDependencyScriptsCandidateTemplate(driver:SqliteDriver,artifacts:ArtifactCatalog,owner:StateOwnerContext,runtime:AuthorizationRuntime,
  input:{runId:string;candidateItemId:string;sourceCheckpointId:string;dependencyPlanRef:string;resultSourceRef:string},signal?:AbortSignal) {
  assertActiveStateOwner(driver,owner);const reads=signal?artifacts.withReadSignal(signal):artifacts;
  const source=await readRetainedDependencyCandidate(driver,reads,input.runId,{candidateItemId:input.candidateItemId,sourceCheckpointId:input.sourceCheckpointId,
    dependencyPlanRef:input.dependencyPlanRef,resultSourceRef:input.resultSourceRef,releaseKeys:runtime.releaseKeys,signal});
  return selectRegisteredCandidateTemplate(driver,reads,owner,runtime,source);
}

/** Pure Stop-source composition, never permission. Current direct denial is
 * rebuilt by the exact same source/policy/initial-template algorithm as
 * prepare. Historical direct denial requires its original durable evidence;
 * today's mutable Run cannot supply a past snapshot or an observation time. */
export async function readDependencyScriptDenialCause(driver:SqliteDriver,artifacts:ArtifactCatalog,runId:string,
  input:{observedAt:string;retained?:{candidateItemId:string;sourceCheckpointId:string;dependencyPlanRef:string;resultSourceRef:string;
    policyChannelEvidenceRef?:string}},signal?:AbortSignal) {
  const reads=signal?artifacts.withReadSignal(signal):artifacts;reads.assertReadActive();
  assertControlWireJson(input);controlWireRecord(input,['observedAt'],['retained']);
  if(Object.hasOwn(input,'retained')){const locator=controlWireRecord(input.retained,['candidateItemId','sourceCheckpointId','dependencyPlanRef','resultSourceRef'],['policyChannelEvidenceRef']);
    controlWireText(locator.candidateItemId,256);controlWireText(locator.sourceCheckpointId,256);
    for(const key of ['dependencyPlanRef','resultSourceRef',...(locator.policyChannelEvidenceRef===undefined?[]:['policyChannelEvidenceRef'])])controlWireRef(locator[key]);}
  const options=immutableSnapshot(input);parseCanonicalTime(options.observedAt);
  const current=readRun(driver,runId),runtime=await retainedRuntime(reads,current);
  reads.assertReadActive();
  const source=options.retained?await readRetainedDependencyCandidate(driver,reads,runId,{candidateItemId:options.retained.candidateItemId,
    sourceCheckpointId:options.retained.sourceCheckpointId,dependencyPlanRef:options.retained.dependencyPlanRef,resultSourceRef:options.retained.resultSourceRef,releaseKeys:runtime.releaseKeys,signal}):
    await readCurrentDependencyCandidate(driver,reads,runId,{releaseKeys:runtime.releaseKeys,signal});
  const at=options.observedAt;
  if(source.policy.installScriptsPolicy!=='exact_lockfile_grant'||!source.policy.installScriptsGrantRef||!source.plan.allowInstallScripts)return;
  const {readDependencyScriptsTemplateHistoryData}=await import('./dependency-script-history.js');
  const initial=await (await import('./dependency-initial-consent.js')).readInitialDependencyScriptsConsent(driver,reads,source,signal);
  if(initial.template.provenance.kind!=='run_admission')invalid('denial lacks complete original admission consent');
  const assertUnchanged=(connection:SqliteConnection|SqliteDriver)=>{
    reads.assertReadActive();source.assertUnchanged(connection);initial.assertUnchanged(connection);
  };
  // Keep the original preparation priority: a still-covering admission grant
  // does not become a new policy refusal merely because today is another cut.
  if(initial.template.runId===source.run.id&&sameDependencyScriptInputs(initial.template.scriptConditions,source.conditions)&&at<initial.template.expiresAt&&
    source.candidateOrdinal<initial.template.maxCandidateGenerations){assertUnchanged(driver);return;}
  const history=await decisions(driver,reads,runtime,source),last=history.at(-1);
  const finalCut=(connection:SqliteConnection|SqliteDriver)=>{assertUnchanged(connection);for(const original of history)original.assertUnchanged(connection);};
  if(last?.decision.decision==='deny'){
    if(at<last.control.committedAt)invalid('denial observation predates its original registered decision');
    const evidence=last.evidence;
    finalCut(driver);
    return Object.freeze({kind:'dependency_install_scripts_denial' as const,origin:'registered_decision' as const,runId,opId:last.request.opId,
      policyChannelEvidenceRef:canonicalSha256(evidence),policyChannelEvidenceDigest:evidence.evidenceDigest,evidence,
      request:last.request,target:last.target,sourceRunSnapshotRef:last.request.sourceRunSnapshotRef,
      decision:last.decision,decisionRef:canonicalSha256(last.decision),waitingSubjectRef:last.decision.waitingSubjectRef,
      firstResponseRef:last.control.responseRef,firstResponse:immutableSnapshot(last.response),control:immutableSnapshot(last.control),
      plans:[] as readonly PlannedArtifact[],assertUnchanged:finalCut});
  }
  if(last?.template&&at<last.template.expiresAt){finalCut(driver);return;}
  if(await alreadyClaimed(reads,source)){finalCut(driver);return;}
  if(options.retained){
    const ref=options.retained.policyChannelEvidenceRef;
    if(ref===undefined){finalCut(driver);return;}
    const evidence=decodeDependencyScriptPolicyEvidence(await readCanonicalArtifact(reads,ref));
    if(evidence.runId!==runId||evidence.effectiveDisposition!=='deny'||evidence.evaluatedAt!==at)invalid('retained denial evidence does not bind its original observation');
    const original=await material(driver,reads,runtime,runId,evidence.requestRef);
    if(original.source.candidate.itemId!==source.candidate.itemId||original.source.checkpoint.id!==source.checkpoint.id||
      original.source.dependencyPlanRef!==source.dependencyPlanRef||original.source.candidate.resultSourceRef!==source.candidate.resultSourceRef)
      invalid('retained denial substitutes another candidate source');
    requireEqual(evidence,policyFor(original.source,original.policy,original.request,original.target,at),'exact original direct script denial');
    if(at<original.original.updatedAt||at>=original.original.deadlineAt)invalid('retained direct denial is outside its original source lifetime');
    const unchanged=(connection:SqliteConnection|SqliteDriver)=>{finalCut(connection);original.source.assertUnchanged(connection);};
    unchanged(driver);
    return Object.freeze({kind:'dependency_install_scripts_denial' as const,origin:'frozen_policy' as const,runId,opId:original.request.opId,
      policyChannelEvidenceRef:ref,policyChannelEvidenceDigest:evidence.evidenceDigest,evidence,request:original.request,target:original.target,
      sourceRunSnapshotRef:original.request.sourceRunSnapshotRef,plans:[] as readonly PlannedArtifact[],assertUnchanged:unchanged});
  }
  if(at<source.run.updatedAt||at>=source.run.deadlineAt){finalCut(driver);return;}
  const snapshot=planCanonicalArtifact(source.run,'cliq-original-run-snapshot-v1'),binding=originalBinding(source,snapshot.ref),target=targetFor(source,binding);
  const request=requestFor(source,binding,target,source.run.frontierRef!),policy=await readPolicyData(reads,source,runtime),evidence=policyFor(source,policy,request,target,at);
  if(evidence.effectiveDisposition!=='deny'){finalCut(driver);return;}
  const plans=Object.freeze([snapshot,planCanonicalArtifact(target,target.format),planCanonicalArtifact(request,request.format),planCanonicalArtifact(evidence,evidence.format)]);
  finalCut(driver);
  return Object.freeze({kind:'dependency_install_scripts_denial' as const,origin:'frozen_policy' as const,runId,opId:request.opId,
    policyChannelEvidenceRef:canonicalSha256(evidence),policyChannelEvidenceDigest:evidence.evidenceDigest,evidence,request,target,
    sourceRunSnapshotRef:snapshot.ref,plans,assertUnchanged:finalCut});
}
export const prepareDependencyScriptApproval=stateOperation('RECOVERY_REQUIRED',async(driver:SqliteDriver,artifacts:ArtifactCatalog,owner:StateOwnerContext,
  runtime:AuthorizationRuntime,input:{runId:string;expectedRunRevision:number},signal?:AbortSignal)=>{
  const reads=signal?artifacts.withReadSignal(signal):artifacts;assertActiveStateOwner(driver,owner);
  const run=readRun(driver,input.runId);
  if(run.revision!==input.expectedRunRevision)throw new KernelStorageError('REVISION_CONFLICT','script approval source revision changed');
  if(run.status==='waiting'&&run.waitingReason==='approval'&&run.waitingOnRef){
    const wait=await readDependencyScriptApprovalWait(driver,reads,runtime,run.id,run.waitingOnRef);assertDependencyScriptWaitingRun(wait.waitingRun,run);
    wait.source.assertUnchanged(driver);reads.assertReadActive();assertActiveStateOwner(driver,owner);
    return {disposition:'waiting' as const,run};
  }
  const source=await readCurrentDependencyCandidate(driver,reads,run.id,{releaseKeys:runtime.releaseKeys,signal});
  if(source.policy.installScriptsPolicy!=='exact_lockfile_grant'||!source.policy.installScriptsGrantRef||source.run.parentCancellationRef)
    throw new KernelStorageError('STATE_TRANSITION_INVALID','a scriptless or cancelling policy cannot request scripts');
  const active=assertActiveStateOwner(driver,owner);
  if(active.runtimeBundleRef!==canonicalSha256(source.bundle)||active.runtimeBundleManifestDigest!==source.bundle.manifestDigest)invalid('current owner has another signed runtime');
  const freshData=()=>{reads.assertReadActive();source.assertUnchanged(driver);assertActiveStateOwner(driver,owner);};
  const at=sampleCanonicalNow();
  checkPreparationTime(driver,owner,source,at);
  if(at>=source.run.deadlineAt)throw new KernelStorageError('LEASE_FENCED','script consent preparation expired');
  const initial=await (await import('./dependency-initial-consent.js')).readInitialDependencyScriptsConsent(driver,reads,source,signal);
  if(initial.template.runId===source.run.id&&initial.template.provenance.kind==='run_admission'&&sameDependencyScriptInputs(initial.template.scriptConditions,source.conditions)&&
    at<initial.template.expiresAt&&source.candidateOrdinal<initial.template.maxCandidateGenerations){freshData();return {disposition:'authorized' as const,templateRef:initial.templateRef};}
  const existing=await decisions(driver,reads,runtime,source),last=existing.at(-1);
  if(last?.decision.decision==='deny'){freshData();return {disposition:'denied' as const,run:source.run};}
  if(last?.template&&at<last.template.expiresAt){freshData();return {disposition:'authorized' as const,templateRef:last.templateRef!};}
  if(await alreadyClaimed(reads,source))throw new KernelStorageError('STATE_TRANSITION_INVALID','claimed dependency scripts cannot acquire another consent/dispatch');
  const snapshot=planCanonicalArtifact(source.run,'cliq-original-run-snapshot-v1'),b=originalBinding(source,snapshot.ref),target=targetFor(source,b);
  const request=requestFor(source,b,target,source.run.frontierRef!),policy=await readPolicyData(reads,source,runtime);
  const evidence=policyFor(source,policy,request,target,at);
  if(evidence.effectiveDisposition==='deny'){freshData();return {disposition:'denied' as const,run:source.run};}
  const m={source,original:source.run,request,target,policy,frontier:frontierFor(source)},wait=waitingFor(m,evidence),waitPlan=planCanonicalArtifact(wait,'cliq-dependency-script-approval-wait-v1');
  const metadata=await publish(reads,[snapshot,planCanonicalArtifact(target,target.format),planCanonicalArtifact(request,request.format),planCanonicalArtifact(evidence,evidence.format),waitPlan]);
  let outcome:ReturnType<typeof advanceTimeFence>|undefined,updated:Run|undefined;
  driver.transaction(connection=>{
    reads.assertReadActive();assertActiveStateOwner(connection,owner);source.assertUnchanged(connection);
    const c=sampleCanonicalNow();outcome=advanceTimeFence(connection,owner.ownerEpoch,c);if(outcome!=='healthy')return;
    assertChildAncestryRelease(connection,run.id,c);if(c<at||c>=source.run.deadlineAt)throw new KernelStorageError('LEASE_FENCED','script wait preparation expired');
    for(const value of metadata)insertArtifactMetadata(connection,value,c);
    const cp=source.checkpoint;
    connection.prepare(`INSERT INTO checkpoints(id,schema_version,run_id,based_on_run_revision,run_item_seq,context_manifest_ref,journal_seq,workspace_state_ref,created_at,reason)
      VALUES(?,1,?,?,?,?,?,?,?,'auto')`).run(dependencyScriptWaitCheckpointId(waitPlan.ref),run.id,run.revision,cp.runItemSeq,cp.contextManifestRef,cp.journalSeq,cp.workspaceStateRef,at);
    connection.prepare("UPDATE runs SET status='waiting',waiting_reason='approval',waiting_on_ref=?,latest_checkpoint_id=?,revision=revision+1,updated_at=? WHERE id=?")
      .run(waitPlan.ref,dependencyScriptWaitCheckpointId(waitPlan.ref),at,run.id);updated=readRun(connection,run.id);appendRunStateEvent(connection,updated,at);
  });requireHealthyFence(outcome);if(!updated)invalid('wait did not commit');return {disposition:'waiting' as const,run:updated};
});
export const approveDependencyScripts=stateOperation('INVALID_REQUEST',async(driver:SqliteDriver,artifacts:ArtifactCatalog,owner:StateOwnerContext,runtime:AuthorizationRuntime,
  input:{request:RunApproveRequestV1;identity:AuthenticatedControlIdentity},signal?:AbortSignal)=>{
  const request=decodeInstalledControlRequest(input.request),identity=input.identity;if(request.method!=='run.approve')throw new TypeError('script approval requires run.approve');
  const reads=signal?artifacts.withReadSignal(signal):artifacts;assertActiveStateOwner(driver,owner);
  let channel=await validateControlChannelClosure(reads,owner,identity);
  if(readSessionPrincipalId(driver,readRun(driver,request.runId).sessionId)!==identity.principalId)throw new KernelStorageError('NOT_FOUND','script approval Run is unavailable');
  const replay=async()=>{
    const prior=readControlRequest(driver,identity.principalId,'run.approve',request.requestId);if(!prior)return;
    if(prior.requestDigest!==request.requestDigest)throw new KernelStorageError('REQUEST_ID_CONFLICT','script approval request id names different bytes');
    const response=await readCanonicalArtifact<{protocolVersion:1;ok:true;result:{method:'run.approve';decisionRef:string}}>(reads,prior.responseRef);
    if(response.protocolVersion!==1||response.ok!==true||response.result?.method!=='run.approve')invalid('replay lacks its original response');
    const old=await readDependencyScriptApproval(driver,reads,runtime,request.runId,response.result.decisionRef);
    if(old.decision.requestId!==request.requestId||old.decision.requestDigest!==request.requestDigest||old.decision.principalId!==identity.principalId||!same(old.control,prior))invalid('replay response belongs to another authenticated request');
    const currentChannel=await validateControlChannelClosure(reads,owner,identity);reads.assertReadActive();assertActiveStateOwner(driver,owner);
    if(currentChannel.channel.transport.kind==='uds_peer')assertCurrentControlFrame(owner,identity);old.assertUnchanged(driver);
    return {replayed:true,response:old.response};
  };const retained=await replay();if(retained)return retained;
  const m=await readDependencyScriptApprovalWait(driver,reads,runtime,request.runId,request.waitingOnRef);
  requireEqual(readRun(driver,request.runId),m.waitingRun,'script current original waiting Run');
  if(request.expectedRevision!==m.waitingRun.revision)throw new KernelStorageError('REVISION_CONFLICT','script approval revision changed');
  const at=sampleCanonicalNow(),active=assertActiveStateOwner(driver,owner);
  if(active.runtimeBundleRef!==canonicalSha256(m.source.bundle)||active.runtimeBundleManifestDigest!==m.source.bundle.manifestDigest||
    canonicalSha256(runtime.bundle)!==active.runtimeBundleRef)invalid('current approval owner has another signed runtime');
  checkPreparationTime(driver,owner,m.source,at,identity,channel.channel.transport.kind==='uds_peer');
  if(at<m.wait.createdAt||at>=m.original.deadlineAt)throw new KernelStorageError('LEASE_FENCED','script approval has expired');
  const inspector=supervisorInspectorIdentity(active),inspectorPlan=planCanonicalArtifact(inspector,inspector.format);
  const core={schemaVersion:1 as const,format:'cliq-approval-decision-v1' as const,decisionId:identityHash(identity.principalId,request.runId,request.waitingOnRef,request.requestId,request.requestDigest),
    principalId:identity.principalId,channelIdentityRef:identity.channelIdentityRef,channelIdentityDigest:identity.channelIdentityDigest,stateOwnerEpoch:owner.ownerEpoch,
    supervisorInstanceId:active.supervisorInstanceId,inspectorIdentityRef:inspectorPlan.ref,inspectorIdentityDigest:inspector.identityDigest,runId:request.runId,
    waitingSubjectRef:request.waitingOnRef,waitingSubjectDigest:request.waitingOnRef,frontierRef:m.request.frontierRef,subject:m.wait.subject,subjectDigest:canonicalSha256(m.wait.subject),
    requestId:request.requestId,requestDigest:request.requestDigest,expectedRunRevision:request.expectedRevision,decision:request.decision,
    ...(request.ttlMs===undefined?{}:{requestedTtlMs:request.ttlMs}),...(request.decision==='allow'?{grantExpiresAt:addCanonicalDuration(at,Math.min(request.ttlMs??3600000,parseCanonicalTime(m.original.deadlineAt)-parseCanonicalTime(at)))}:{}),createdAt:at};
  const d=decodeDependencyScriptApprovalDecision({...core,decisionDigest:canonicalSha256(core)});validateDecision(m,d);
  const decisionPlan=planCanonicalArtifact(d,d.format),item=decisionItem(m,d),{requestDigest:_digest,...wireCore}=request;
  const requestPlan=planCanonicalArtifact(wireCore,'cliq-run-approve-request-v1');if(requestPlan.ref!==request.requestDigest)invalid('approval wire digest changed');
  const metadata=await publish(reads,[requestPlan,inspectorPlan,decisionPlan]);
  const existing=m.source.items.map(row=>({itemSeq:row.itemSeq,itemRef:row.payloadRef,item:m.decodedItems.get(row.itemId)!}));
  const plan=await prepareContinuationCommit(reads,{context:m.source.context,existingItems:existing.slice(0,m.source.checkpoint.runItemSeq),items:[item],frontier:m.frontier,
    checkpointId:dependencyScriptDecisionCheckpointId(decisionPlan.ref),workspaceStateRef:m.source.checkpoint.workspaceStateRef});
  // The wait added no item. The decision is appended at that same full prefix.
  const {waitingOnRef:_wait,waitingReason:_reason,...current}=m.waitingRun;
  const next:Run={...current,...plan.runUpdate,status:'queued',revision:current.revision+1,updatedAt:at};
  const response={protocolVersion:1 as const,ok:true as const,result:{method:'run.approve' as const,decisionRef:decisionPlan.ref,
    snapshot:{schemaVersion:1 as const,operation:m.source.spec.operation,run:next,latestRunItemSeq:plan.throughItemSeq}}};
  const responsePlan=planCanonicalArtifact(response,'cliq-control-response-v1'),template=templateFor(m,d,responsePlan.ref);
  metadata.push(...plan.metadata,...await publish(reads,[responsePlan,...(template?[planCanonicalArtifact(template,template.format)]:[])]));
  await readSupervisorInspector(reads,active,m.source.assembly,{...d,observedAt:at});channel=await validateControlChannelClosure(reads,owner,identity);
  let outcome:ReturnType<typeof advanceTimeFence>|undefined,committed=false;
  driver.transaction(connection=>{
    reads.assertReadActive();assertActiveStateOwner(connection,owner);if(channel.channel.transport.kind==='uds_peer')assertCurrentControlFrame(owner,identity);
    if(readControlRequest(connection,identity.principalId,'run.approve',request.requestId))return;
    m.source.assertUnchanged(connection);requireEqual(readRun(connection,request.runId),m.waitingRun,'script still-current waiting Run');
    const c=sampleCanonicalNow();outcome=advanceTimeFence(connection,owner.ownerEpoch,c);if(outcome!=='healthy')return;
    assertChildAncestryRelease(connection,request.runId,c);
    if(c<at||c>=(d.grantExpiresAt??m.original.deadlineAt)||c>=m.original.deadlineAt)throw new KernelStorageError('LEASE_FENCED','script approval is no longer current');
    for(const value of [...metadata,...channel.metadata])insertArtifactMetadata(connection,value,c);
    plan.commit(connection,m.waitingRun,m.checkpoint.journalSeq,at);
    connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,revision=revision+1,updated_at=? WHERE id=?").run(at,request.runId);
    insertControlRequest(connection,{...identity,method:'run.approve',requestId:request.requestId,requestDigest:request.requestDigest,responseRef:responsePlan.ref,committedAt:c});
    appendRunStateEvent(connection,next,at);committed=true;
  });requireHealthyFence(outcome);if(!committed){const raced=await replay();if(raced)return raced;invalid('approval lost its original current cut');}
  return {replayed:false,response};
});

/** Original signed data configuration only. This does not create a current
 * owner, native release or new trust root. */
async function retainedRuntime(artifacts:ArtifactCatalog,run:Run):Promise<AuthorizationRuntime> {
  const {decodeRunSpec}=await import('./decoders.js');
  const {decodeRetainedRunAssembly}=await import('../model/run-assembly.js');
  const spec=decodeRunSpec(await readCanonicalArtifact(artifacts,run.specRef));
  const assembly=decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts,spec.assemblyRef));
  const bundle=await readCanonicalArtifact<AuthorizationRuntime['bundle']>(artifacts,assembly.runtime.runtimeBundleRef);
  if(bundle.manifestDigest!==assembly.runtime.runtimeBundleManifestDigest)invalid('historical runtime differs from its original assembly');
  return {bundle,releaseKeys:artifacts.releaseTrustRoots()};
}
/** Recovery composes this leaf source reader without reopening full recovery.
 * Every consent is still bound to its exact SQL item/control/Checkpoint. */
export async function validateDependencyScriptApprovalHistory(driver:SqliteDriver,artifacts:ArtifactCatalog,
  input:{run:Run;items:ReadonlyMap<string,ContinuationItem>}) {
  requireEqual(readRun(driver,input.run.id),input.run,'script owning recovery Run');
  const runtime=await retainedRuntime(artifacts,input.run);
  const rows=driver.prepare("SELECT item_id,payload_ref FROM items WHERE run_id=? AND kind='policy_decision' ORDER BY item_seq")
    .all<{item_id:string;payload_ref:string}>(input.run.id);
  if(rows.length!==[...input.items.values()].filter(item=>item.kind==='policy_decision').length)invalid('recovery omitted or added a registered policy item');
  const waits=new Set<string>();
  for(const row of rows) {
    const item=input.items.get(row.item_id);
    if(item?.kind!=='policy_decision'||item.runId!==input.run.id||canonicalSha256(item)!==row.payload_ref)invalid('recovery changed its registered policy item');
    if(item.subjectKind!=='dependency_install_scripts')continue;
    const exact=decodeDependencyScriptDecisionItem(item);
    if(waits.has(exact.waitingSubjectRef))invalid('one original wait has multiple decisions');waits.add(exact.waitingSubjectRef);
    const original=await readDependencyScriptApproval(driver,artifacts,runtime,input.run.id,exact.decisionRef);
    requireEqual(original.item,exact,'script original recovery decision');original.assertUnchanged(driver);
  }
  if(input.run.status==='waiting'&&input.run.waitingReason==='approval'&&input.run.waitingOnRef) {
    const raw=await readCanonicalArtifact<{subject?:{kind?:string}}>(artifacts,input.run.waitingOnRef);
    if(raw.subject?.kind==='dependency_install_scripts') {
      const wait=await readDependencyScriptApprovalWait(driver,artifacts,runtime,input.run.id,input.run.waitingOnRef);
      assertDependencyScriptWaitingRun(wait.waitingRun,input.run);wait.source.assertUnchanged(driver);
    }
  }
  requireEqual(readRun(driver,input.run.id),input.run,'script completed recovery Run');
}

/** The ordinary Stop producer may only fence this already validated wait. It
 * does not manufacture a user approval, template, dispatch or death proof. */
export async function readDependencyScriptWaitingRun(driver:SqliteDriver,artifacts:ArtifactCatalog,run:Run) {
  if(run.status!=='waiting'||run.waitingReason!=='approval'||!run.waitingOnRef||run.nextStep!=='verify')invalid('has no candidate consent wait');
  const runtime=await retainedRuntime(artifacts,run);
  const original=await readDependencyScriptApprovalWait(driver,artifacts,runtime,run.id,run.waitingOnRef);
  assertDependencyScriptWaitingRun(original.waitingRun,run);original.source.assertUnchanged(driver);return original;
}

function checkPreparationTime(driver:SqliteDriver,owner:StateOwnerContext,source:DependencyCandidateData,at:string,
  identity?:AuthenticatedControlIdentity,uds=false) {
  const active=assertActiveStateOwner(driver,owner);
  if(at>=active.acquiredAt&&at>=source.run.updatedAt)return;
  let outcome:ReturnType<typeof advanceTimeFence>|undefined;
  driver.transaction(connection=>{
    assertActiveStateOwner(connection,owner);source.assertUnchanged(connection);
    if(uds)assertCurrentControlFrame(owner,identity!);
    outcome=advanceTimeFence(connection,owner.ownerEpoch,at);
  });requireHealthyFence(outcome);throw new KernelStorageError('LEASE_FENCED','script consent preparation precedes its original cut');
}

async function readPolicyData(artifacts:ArtifactCatalog,source:DependencyCandidateData,runtime:AuthorizationRuntime) {
  const policy=await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts,source.spec.policyRef);
  const manifest=await readCanonicalArtifact<ToolContractManifestV1>(artifacts,source.assembly.tools.manifestRef);
  if(manifest.schemaVersion!==1||manifest.format!=='cliq-tool-contracts-v1'||!exactKeys(manifest,['schemaVersion','format','entries','manifestDigest'])||
    canonicalSha256(Object.fromEntries(Object.entries(manifest).filter(([k])=>k!=='manifestDigest')))!==manifest.manifestDigest||manifest.manifestDigest!==source.assembly.tools.manifestDigest)
    invalid('policy tool manifest differs from its complete original assembly');
  const profile=await readCanonicalArtifact<PolicyEngineProfileV1>(artifacts,policy.engine.profileRef);
  await readToolRuntimeAuthority(artifacts,{assembly:source.assembly,bundle:source.bundle,policy,profile,tools:manifest.entries,
    releaseKeys:runtime.releaseKeys,resources:source.profile.resources});
  return policy;
}
