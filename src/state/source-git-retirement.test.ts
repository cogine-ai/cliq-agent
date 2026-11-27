// Pure retained-data audit only. No StateOwner, auth, native resources or
// evidence authority is created. All decoding uses current production code.
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { ArtifactCatalog } from './artifacts.js';
import type { SourceInspectionAttemptV1, SourceInspectionRetirementEvidenceV1 } from '../kernel/execution.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { normalizeSourceInspectionRequest, sourceInspectionIntentDigest } from './source-target.js';
import { readSourceGitRetirementClosure } from './source-git-retirement.js';
test('retired source audit rejects missing original plan/spec bytes and a rehashed plan digest', async () => {
const objects=new Map<string, Buffer>(),reads: string[]=[];
const save=(value: unknown)=>{const bytes=canonicalJsonBytes(value),ref=canonicalSha256(value);objects.set(ref,bytes);return ref;};
// This inert CAS data adapter and real SQLite request index cannot mint any
// native, StateOwner, auth or resource-retirement capability.
const artifacts={async readCanonical(ref: string){reads.push(ref);const bytes=objects.get(ref);assert(bytes,'missing inert data artifact '+ref);assert.equal(createHash('sha256').update(bytes).digest('hex'),ref);return JSON.parse(bytes.toString());},
 async readBoundedBytes(ref: string,bound: number){reads.push(ref);const bytes=objects.get(ref);assert(bytes,'missing inert data artifact '+ref);assert(bytes.length<=bound);assert.equal(createHash('sha256').update(bytes).digest('hex'),ref);return Buffer.from(bytes);}};
const principalId='principal',grantId=identityHash('data-only-grant'),at='2026-10-25T00:00:00.000Z';
const requestCore={protocolVersion:1,requestId:'01900000-0000-7000-8000-000000000002',method:'run.submit',admissionKey:'a'.repeat(43),sessionId:'session',expectedContextRevision:1,
 workspacePath:'/workspace',objective:'inspect data',model:{provider:'ollama',model:'local'},policyMode:'default',verifiers:[],dependency:{mode:'none'},sourceIncludes:[],sourceExcludes:[],
 registeredMcpServerIds:[],skillIds:[],allowUnverified:true,sourceInspectionGrantId:grantId};
const wire={...requestCore,requestDigest:canonicalSha256(requestCore)},normalized=normalizeSourceInspectionRequest(wire),request=normalized.request;
const admissionIntentDigest=sourceInspectionIntentDigest(principalId,request),inspectionId=identityHash('cliq-source-inspection-v1',principalId,request.method,request.admissionKey,admissionIntentDigest);
const workspace={schemaVersion:1,format:'cliq-workspace-identity-v1',ownerPrincipalId:principalId,platform:'linux',kind:'live',canonicalRootPath:'/workspace',
 rootIdentity:{deviceId:'1',fileId:'2',ownerUid:0},repositoryIdentityRef:'a'.repeat(64),repositoryIdentityDigest:'b'.repeat(64),identityDigest:''};workspace.identityDigest=digestOmitting(workspace,'identityDigest');
const profile={schemaVersion:1,format:'cliq-sandbox-profile-v1',backend:'linux_namespace',allowedOwners:['source_inspection'],filesystemPolicy:'typed_launch_spec_only',hostFilesystemReachability:'none',
 networkAtSpawn:'none',networkAfterRelease:'typed_broker_only',credentialReachability:'typed_broker_only',stateRootReachability:'none',inheritedHostEnvironment:false,resources:{...DEFAULT_SANDBOX_RESOURCES},profileDigest:''};profile.profileDigest=digestOmitting(profile,'profileDigest');
const receipt={schemaVersion:1,grantId,ownerPrincipalId:principalId,targetDigest:'a'.repeat(64),consumer:{kind:'source_inspection',inspectionId,admissionIntentDigest},consumedAt:at,receiptDigest:''};receipt.receiptDigest=digestOmitting(receipt,'receiptDigest');
const target={schemaVersion:2,format:'cliq-source-inspection-target-v2',principalId,method:'run.submit',admissionKey:request.admissionKey,admissionIntentDigest,
 originalRequestRef:save(wire),originalRequestDigest:normalized.originalRequestDigest,sessionId:'session',expectedContextRevision:1,workspaceIdentityRef:save(workspace),workspaceIdentityDigest:workspace.identityDigest,
 sourceReadGrantRefs:[],runtimeBundleRef:'c'.repeat(64),runtimeBundleManifestDigest:'d'.repeat(64),sandboxProfileRef:save(profile),sandboxProfileDigest:profile.profileDigest,
 inspectionGrantId:grantId,inspectionReceiptRef:save(receipt),inspectionReceiptDigest:receipt.receiptDigest,ignoreReadConsents:[],targetDigest:''};target.targetDigest=digestOmitting(target,'targetDigest');const targetRef=save(target);
const input={schemaVersion:2,format:'cliq-source-inspection-input-v2',inspectionId,targetRef,targetDigest:target.targetDigest,repositoryIdentityDigest:workspace.repositoryIdentityDigest,
 inspectionGrantId:grantId,inspectionReceiptRef:target.inspectionReceiptRef,inspectionReceiptDigest:receipt.receiptDigest,recipe:'cliq-source-git-inspection-v1',snapshotPolicy:'ephemeral_native_sealed_shards',resources:{...DEFAULT_SANDBOX_RESOURCES},inputDigest:''};input.inputDigest=digestOmitting(input,'inputDigest');const inputRef=save(input);
const row={schemaVersion:1,inspectionId,attempt:1,principalId,method:'run.submit',admissionKey:request.admissionKey,admissionIntentDigest,targetRef,targetDigest:target.targetDigest,
 workspaceIdentityDigest:workspace.identityDigest,stateOwnerEpoch:1,supervisorInstanceId:'original',stagingNonceDigest:'e'.repeat(64),stagingIdentity:{deviceId:'1',fileId:'2',ownerUid:0,mode:448},
 cancelRequested:false,rowVersion:3,createdAt:at,deadlineAt:'2026-10-25T01:00:00.000Z',updatedAt:'2026-10-25T00:00:01.000Z',phase:'retired',inputRef,inputDigest:input.inputDigest,
 plan:{launchNonceDigest:'1'.repeat(64),containmentPlanRef:'2'.repeat(64),containmentPlanDigest:'3'.repeat(64),sandboxLaunchSpecRef:'4'.repeat(64),sandboxLaunchSpecDigest:'5'.repeat(64),
 reservedBackendIdentity:{kind:'linux',cgroupPath:'/owned/data-only',cgroupId:'4',deviceId:'3',fileId:'4',ownerUid:0,pidNamespaceReservationId:'source-pending:'+'e'.repeat(64),subreaperStartToken:'linux-subreaper:1:linux-proc-start-ticks:1'}},
 outcome:{kind:'failed',errorResponseRef:'f'.repeat(64)},retirementEvidenceRef:'0'.repeat(64),retiredAt:'2026-10-25T00:00:01.000Z',rowDigest:''};row.rowDigest=digestOmitting(row,'rowDigest');
const observedAtMs=Date.parse(row.retiredAt),observation={observedAtMs,inspectionId,stagingNonceDigest:row.stagingNonceDigest,targetRef,inputIntentRef:inputRef,reserved:1,blocked:0,released:0,continued:0,
 origin:'original_owner_joined',lastBirthKind:12,originalControllerPid:1,originalControllerStartToken:'linux-proc-start-ticks:1',cgroupDeviceId:'3',cgroupId:'4',launchNonceDigest:row.plan.launchNonceDigest,
 containmentPlanRef:null,sandboxLaunchRef:null,sandboxLaunchDigest:null,containment:null};
const evidence={captureOwnerClosure:{kind:'local_resources_joined',stateOwnerEpoch:1,supervisorInstanceId:'original'},observedAt:row.retiredAt,
 processClosure:{kind:'source_native_retired',inputRef,inputDigest:input.inputDigest,nativeBirthIdentity:{deviceId:'1',fileId:'9',ownerUid:0},observation}};
const sql=new DatabaseSync(':memory:');sql.exec('CREATE TABLE source_inspection_attempts(inspection_id TEXT,original_request_id TEXT,original_request_digest TEXT)');
sql.prepare('INSERT INTO source_inspection_attempts VALUES(?,?,?)').run(inspectionId,request.requestId,normalized.originalRequestDigest);
try {
  const audit = () => readSourceGitRetirementClosure(sql as unknown as SqliteDriver, artifacts as unknown as ArtifactCatalog,
    row as unknown as Extract<SourceInspectionAttemptV1, { phase: 'retired' }>, evidence as unknown as SourceInspectionRetirementEvidenceV1,
    { runtimeBundleRef: target.runtimeBundleRef, runtimeBundleManifestDigest: target.runtimeBundleManifestDigest });
  assert(!objects.has(row.plan.containmentPlanRef) && !objects.has(row.plan.sandboxLaunchSpecRef));
  await assert.rejects(audit());
  assert(reads.includes(row.plan.containmentPlanRef), 'the actual retained reader must read the original plan');
  row.plan.containmentPlanDigest = '9'.repeat(64); row.rowDigest = digestOmitting(row, 'rowDigest');
  await assert.rejects(audit());
} finally { sql.close(); }
});
