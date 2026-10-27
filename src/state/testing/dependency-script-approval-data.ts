// Inert closed data for decoder/presentation tests; no owner or authority.
import { canonicalSha256 } from '../../kernel/canonical.js';
import type { DependencyScriptConditionsV1 } from '../../kernel/dependency.js';
import { dependencyScriptApprovalOpId, dependencyScriptDecisionItemId } from '../../kernel/dependency-script-approval.js';
const ref = (name: string) => canonicalSha256({ inertFixture: name });
function conditions(): DependencyScriptConditionsV1 {
  return { profile: 'npm-ci-v1', lockfilePath: 'package-lock.json', lockfileDigest: ref('lock'), packageManifestDigest: ref('package'), bindingGyp: { kind: 'absent' },
    source: { sourceManifestRef: ref('manifest bytes'), sourceManifestDigest: ref('manifest meaning'), sourceRole: 'base',
      projectedEntriesRef: ref('projection entries'), projectedTreeDigest: ref('projection tree'), sourceProjectionRef: ref('projection'),
      sourceProjectionDigest: ref('projection meaning'), workspaceEntriesRef: ref('complete entries'), workspaceTreeDigest: ref('complete tree'), scriptInputTreeDigest: ref('derived actual program inputs'), privateGit: { kind: 'absent' } },
    execution: { runtimeBundleRef: ref('runtime'), runtimeBundleManifestDigest: ref('runtime meaning'), guestToolchainManifestRef: ref('guest'),
      guestToolchainManifestDigest: ref('guest meaning'), nodeExecutionPath: '/usr/bin/node', nodeExecutableDigest: ref('node'),
      adapterCodeRef: ref('adapter'), npmDataRef: ref('official npm data'), registryTargetsDigest: ref('targets'), environmentDigest: ref('environment') } };
}

// Inert data only. No accepted Run, owner, authorization or native proof.
export function approvalData() {
 const c=conditions(),b={runId:'run',candidateItemId:'candidate',candidateOrdinal:0,sourceCheckpointId:'source-cp',sourceRunSnapshotRef:ref('original Run'),
 workspaceStateRef:ref('workspace state'),resultSourceRef:c.source.sourceManifestRef,dependencyPlanRef:ref('full plan'),dependencyPlanDigest:ref('plan meaning'),lockfileDigest:c.lockfileDigest,scriptConditionsDigest:canonicalSha256(c)};
 const targetCore={...b,schemaVersion:1 as const,format:'cliq-dependency-script-approval-target-v1' as const,workspaceIdentityRef:ref('identity'),workspaceIdentityDigest:ref('identity meaning'),conditions:c,
 execution:{kind:'supervisor_operation' as const,handlerId:'dependency_install_scripts_approval' as const,supervisorEntryId:'supervisor',supervisorEntryVersion:'1',supervisorExecutableDigest:ref('signed supervisor')}};
 const t={...targetCore,targetDigest:canonicalSha256(targetCore)},opId=dependencyScriptApprovalOpId(b);
 const qCore={...b,schemaVersion:1 as const,format:'cliq-dependency-script-approval-request-v1' as const,opId,assemblyRef:ref('assembly'),frontierRef:ref('frontier'),targetRef:canonicalSha256(t),targetDigest:t.targetDigest};
 const q={...qCore,requestDigest:canonicalSha256(qCore)};
 const eCore={schemaVersion:1 as const,format:'cliq-policy-channel-evidence-v1' as const,principalId:'principal',runId:'run',policyRef:ref('policy'),policyDigest:ref('policy meaning'),frontierRef:q.frontierRef,opId,
 requestRef:canonicalSha256(q),requestDigest:q.requestDigest,targetRef:q.targetRef,targetDigest:t.targetDigest,actionClass:'dependency_install_scripts' as const,channel:'named-action' as const,
 identityKey:'dependency_install_scripts/'+c.lockfileDigest,decisionSource:'mode_fallthrough' as const,matchedRuleIds:[],effectiveDisposition:'allow' as const,evaluatedAt:'2026-01-01T00:00:00.000Z'};
 const e={...eCore,evidenceDigest:canonicalSha256(eCore)};
 const w={schemaVersion:1 as const,kind:'approval' as const,runId:'run',createdFromRevision:3,createdAt:e.evaluatedAt,frontierRef:q.frontierRef,
 subject:{...b,kind:'dependency_install_scripts' as const,reason:'source_conditions_changed' as const,opId,target:q.targetRef,policyChannelEvidenceRef:canonicalSha256(e),policyChannelEvidenceDigest:e.evidenceDigest}};
 const dCore={schemaVersion:1 as const,format:'cliq-approval-decision-v1' as const,decisionId:'decision',principalId:'principal',channelIdentityRef:ref('channel'),channelIdentityDigest:ref('channel meaning'),stateOwnerEpoch:1,
 supervisorInstanceId:'supervisor-instance',inspectorIdentityRef:ref('inspector'),inspectorIdentityDigest:ref('inspector meaning'),runId:'run',waitingSubjectRef:canonicalSha256(w),waitingSubjectDigest:canonicalSha256(w),frontierRef:q.frontierRef,
 subject:w.subject,subjectDigest:canonicalSha256(w.subject),requestId:'00000000-0000-7000-8000-000000000001',requestDigest:ref('wire core'),expectedRunRevision:4,decision:'allow' as const,requestedTtlMs:1000,grantExpiresAt:'2026-01-01T00:00:01.000Z',createdAt:e.evaluatedAt};
 const d={...dCore,decisionDigest:canonicalSha256(dCore)};
 const item={schemaVersion:1 as const,kind:'policy_decision' as const,subjectKind:'dependency_install_scripts' as const,itemId:dependencyScriptDecisionItemId('run',canonicalSha256(d)),runId:'run',opId,principalId:'principal',decisionSource:'interactive_approval' as const,
 waitingSubjectRef:canonicalSha256(w),decisionRef:canonicalSha256(d),policyChannelEvidenceRef:canonicalSha256(e),policyChannelEvidenceDigest:e.evidenceDigest,decision:'allow' as const,createdAt:e.evaluatedAt};
 return {t,q,e,w,d,item};
}
