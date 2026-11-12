// Closed managed-local data. Decoding these records never creates a model
// registration, StateOwner, process, native observation or zero-cost authority.
import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertRequestId, digestOmitting, identityHash, parseCanonicalTime } from './identity.js';
import { assertBoundedJsonValue } from './json.js';
import type { SandboxResourceSpec } from './execution.js';
import type { NormalizedModelCapabilityClaimsV1 } from '../model/capabilities.js';
import { immutableSnapshot } from '../model/immutable.js';

export type LocalModelManifestV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-local-model-manifest-v1'; signerKeyId: string;
  signatureAlgorithm: 'ed25519'; signatureRef: string; provider: 'ollama'; model: string;
  architecture: string; tokenizerRef: string; tokenizerDigest: string;
  files: readonly Readonly<{ canonicalRelativePath: string; contentRef: string; contentDigest: string; sizeBytes: number }>[];
  claims: NormalizedModelCapabilityClaimsV1; modelManifestDigest: string;
}>;
export type LocalModelObjectV1 = Readonly<{ artifactRef: string; artifactDigest: string; sizeBytes: number }> & (
  Readonly<{ kind: 'model_manifest'; logicalPath: 'model-manifest.json' }> |
  Readonly<{ kind: 'model_signature'; logicalPath: 'model-signature'; sizeBytes: 64 }> |
  Readonly<{ kind: 'tokenizer'; logicalPath: 'tokenizer' }> |
  Readonly<{ kind: 'model_file'; logicalPath: string }>);
export type LocalModelObjectClosureV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-local-model-object-closure-v1'; stateRootIdentityRef: string; stateRootIdentityDigest: string;
  objectStoreRootRelativePath: 'local-models/objects'; modelManifestRef: string; modelManifestDigest: string;
  objects: readonly LocalModelObjectV1[]; objectCount: number; totalBytes: number; closureDigest: string;
}>;
export type LocalInferenceServiceSpecV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-local-inference-service-v1'; serviceId: string; ownerPrincipalId: string;
  runtimeBundleRef: string; runtimeBundleManifestDigest: string; executableId: 'ollama_local_inference';
  executableVersion: string; executableDigest: string; modelManifestRef: string; modelManifestDigest: string;
  endpoint: Readonly<{ scheme: 'http'; host: '127.0.0.1' | '[::1]'; port: number }>;
  backend: 'macos_vm' | 'linux_namespace'; sandboxProfileRef: string; sandboxProfileDigest: string;
  resources: SandboxResourceSpec; createdAt: string; serviceSpecCoreDigest: string; serviceSpecDigest: string;
}>;
type LocalModelRegistrationBase = Readonly<{
  schemaVersion: 1; format: 'cliq-local-model-registration-v1'; ownerPrincipalId: string;
  provider: 'ollama'; model: string; registryRevision: number; serviceId: string;
  serviceSpec: LocalInferenceServiceSpecV1; expectedServiceSpecRef: string;
  modelManifest: LocalModelManifestV1; expectedModelManifestRef: string;
  objectClosure: LocalModelObjectClosureV1; expectedObjectClosureRef: string; createdAt: string;
}>;
export type LocalModelRegistrationV1 = LocalModelRegistrationBase & (
  Readonly<{ state: 'active'; registrationDigest: string; retiredAt?: never }> |
  Readonly<{ state: 'retired'; registrationDigest: string; retiredAt: string }>);
type LocalModelRegistryHeadBase = Readonly<{
  schemaVersion: 1; format: 'cliq-local-model-registry-head-v1'; ownerPrincipalId: string;
  provider: 'ollama'; model: string; headRevision: number; committedAt: string; headDigest: string;
}>;
export type LocalModelRegistryHeadV1 = LocalModelRegistryHeadBase & (
  Readonly<{ transition: 'initial'; state: 'active'; headRevision: 1; activeRegistrationRef: string; activeRegistrationDigest: string }> |
  Readonly<{ transition: 'replace'; state: 'active'; predecessorHeadRef: string; predecessorHeadDigest: string;
    activeRegistrationRef: string; activeRegistrationDigest: string; retiredRegistrationRef: string; retiredRegistrationDigest: string }> |
  Readonly<{ transition: 'retire'; state: 'retired'; predecessorHeadRef: string; predecessorHeadDigest: string;
    retiredRegistrationRef: string; retiredRegistrationDigest: string }> |
  Readonly<{ transition: 'reenroll'; state: 'active'; predecessorHeadRef: string; predecessorHeadDigest: string;
    activeRegistrationRef: string; activeRegistrationDigest: string }>);
export type LocalInferenceActivationParticipantV1 =
  Readonly<{ kind: 'run_submission'; requestId: string; requestDigest: string; runSubmitRequestRef: string;
    channelIdentityRef: string; channelIdentityDigest: string; admissionKey: string; admissionIntentDigest: string; joinedAt: string }> |
  Readonly<{ kind: 'run_model_frontier'; runId: string; runRevisionAtJoin: number; frontierRef: string; joinedAt: string }>;
export type LocalInferenceActivationFailureV1 = Readonly<{
  schemaVersion: 1; activationCycleId: string; ownerPrincipalId: string; serviceId: string;
  serviceSpecRef: string; serviceSpecDigest: string; finalAttempt: 1 | 2;
  reason: 'activation_timeout' | 'sandbox_launch_failed' | 'health_mismatch' | 'capability_mismatch' |
    'containment_unprovable' | 'activation_cancelled_for_migration';
  launchIds: readonly string[]; evidenceRefs: readonly string[]; observedAt: string; failureDigest: string;
}>;
type LocalInferenceActivationCycleBase = Readonly<{
  schemaVersion: 1; activationCycleId: string; ownerPrincipalId: string; serviceId: string;
  localModelRegistrationRef: string; localModelRegistrationDigest: string;
  serviceSpecRef: string; serviceSpecDigest: string; cycleOrdinal: number;
  participants: readonly LocalInferenceActivationParticipantV1[]; rowVersion: number; createdAt: string;
}>;
export type LocalInferenceActivationCycleV1 = LocalInferenceActivationCycleBase & (
  Readonly<{ phase: 'starting_launch'; activationAttempt: 1 | 2; launchIds: readonly string[];
    currentLaunchId: string; cycleDigest: string }> |
  Readonly<{ phase: 'retry_wait'; activationAttempt: 1; launchIds: readonly [string];
    retryNotBeforeAt: string; cycleDigest: string }> |
  Readonly<{ phase: 'active'; activationAttempt: 1 | 2; launchIds: readonly string[]; currentLaunchId: string;
    boundaryEvidenceRef: string; finishedAt: string; cycleDigest: string }> |
  Readonly<{ phase: 'failed'; activationAttempt: 1 | 2; launchIds: readonly string[];
    failureDetailRef: string; finishedAt: string; cycleDigest: string }>);
type LocalInferenceServiceLaunchBase = Readonly<{
  schemaVersion: 1; serviceId: string; launchId: string; ownerPrincipalId: string; serviceSpecRef: string;
  serviceSpecDigest: string; supervisorInstanceId: string; activationCycleId: string; activationAttempt: 1 | 2;
  activationNonceDigest: string; containmentPlanRef: string; sandboxLaunchSpecRef: string; nativeInputRef: string;
  rowVersion: number; leaseVersion: number; createdAt: string; activationDeadlineAt: string;
}>;
export type LocalInferenceServiceLaunchV1 = LocalInferenceServiceLaunchBase & (
  Readonly<{ phase: 'reserved' }> |
  Readonly<{ phase: 'preactivated'; processContainmentRef: string }> |
  Readonly<{ phase: 'active'; processContainmentRef: string; boundaryEvidenceRef: string; leaseExpiresAt: string }> |
  Readonly<{ phase: 'revoking'; processContainmentRef: string; boundaryEvidenceRef: string; quiesceId: string }> |
  Readonly<{ phase: 'retired'; retirementKind: 'no_spawn'; retirementEvidenceRef: string; retiredAt: string }> |
  Readonly<{ phase: 'retired'; retirementKind: 'death'; processContainmentRef: string; boundaryEvidenceRef?: string;
    quiesceId: string; retirementEvidenceRef: string; retiredAt: string }>);
export type LocalInferenceBoundaryEvidenceV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-local-inference-boundary-v1'; ownerPrincipalId: string; serviceId: string;
  serviceSpecRef: string; serviceSpecDigest: string; serviceLaunchId: string; runtimeBundleRef: string;
  runtimeBundleManifestDigest: string; executableId: string; executableDigest: string; modelManifestRef: string;
  modelManifestDigest: string; processContainmentRef: string; containmentPlanRef: string;
  sandboxLaunchSpecRef: string; sandboxLaunchSpecDigest: string; backend: 'macos_vm' | 'linux_namespace';
  externalNetworkEgress: 'denied'; loopbackOnly: true; stableServiceIdentityDigest: string;
  inspectorSupervisorInstanceId: string; inspectorIdentityRef: string; inspectorIdentityDigest: string;
  observedAt: string; validThrough: string; evidenceDigest: string;
}>;

export const LOCAL_INFERENCE_ACTIVATION_MS = 120_000;
export const LOCAL_INFERENCE_RETRY_MS = 1000;
export const LOCAL_INFERENCE_PARTICIPANTS = 128;
export const LOCAL_MODEL_PORT_FIRST = 49152;
export const LOCAL_MODEL_PORT_LAST = 65535;

function invalid(): never { throw new TypeError('managed local data differs from its exact closed contract'); }
function object(value: unknown, fields: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'managed local data');
  if (canonicalJsonBytes(value).byteLength > 1_048_576) invalid();
  return controlWireRecord(value, fields, optional);
}
function header(data: Record<string, unknown>, format?: string): void {
  if (data.schemaVersion !== 1 || format !== undefined && data.format !== format) invalid();
}
function digest(data: Record<string, unknown>, member: string): void {
  if (controlWireRef(data[member]) !== digestOmitting(data, member)) invalid();
}
function refs(data: Record<string, unknown>, fields: readonly string[]): void { fields.forEach(field => controlWireRef(data[field])); }
function time(value: unknown): string { const result = controlWireText(value); parseCanonicalTime(result); return result; }
function text(value: unknown): string { return controlWireText(value, 512); }
export function decodeLocalIdentity(value: unknown): string {
  const id = controlWireText(value, 43, 43);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(id) || Buffer.from(id, 'base64url').byteLength !== 32 ||
      Buffer.from(id, 'base64url').toString('base64url') !== id) invalid();
  return id;
}
export function decodeLocalModelPath(value: unknown): string {
  const result = controlWireText(value, 4096);
  if (result.includes('\\') || result.startsWith('/') || result.split('/').length > 64 ||
      result.split('/').some(part => part === '' || part === '.' || part === '..' || Buffer.byteLength(part) > 255)) invalid();
  return result;
}
function claims(value: unknown): NormalizedModelCapabilityClaimsV1 {
  const data = controlWireRecord(value, ['nativeToolCalling', 'streaming', 'trustedUsageEvidence', 'contextLimitTokens', 'maxOutputTokens']);
  for (const key of ['nativeToolCalling', 'streaming', 'trustedUsageEvidence']) if (typeof data[key] !== 'boolean') invalid();
  const context = controlWireInteger(data.contextLimitTokens, 32768);
  controlWireInteger(data.maxOutputTokens, 1, Math.floor(context / 4));
  return data as NormalizedModelCapabilityClaimsV1;
}
export function localModelManifestDigest(value: Omit<LocalModelManifestV1, 'modelManifestDigest'> | LocalModelManifestV1): string {
  const { modelManifestDigest: _digest, signatureRef: _signature, ...core } = value as LocalModelManifestV1;
  return canonicalSha256(core);
}
export function decodeLocalModelManifest(value: unknown): LocalModelManifestV1 {
  const data = object(value, ['schemaVersion', 'format', 'signerKeyId', 'signatureAlgorithm', 'signatureRef', 'provider', 'model',
    'architecture', 'tokenizerRef', 'tokenizerDigest', 'files', 'claims', 'modelManifestDigest']);
  header(data, 'cliq-local-model-manifest-v1');
  if (data.provider !== 'ollama' || data.signatureAlgorithm !== 'ed25519') invalid();
  for (const key of ['signerKeyId', 'model', 'architecture']) text(data[key]);
  refs(data, ['signatureRef', 'tokenizerRef', 'tokenizerDigest', 'modelManifestDigest']);
  if (data.tokenizerRef !== data.tokenizerDigest || !Array.isArray(data.files) || data.files.length === 0) invalid();
  claims(data.claims);
  let previous = ''; const paths = new Set<string>(), objects = new Set<string>([data.tokenizerRef as string, data.signatureRef as string]);
  if (objects.size !== 2) invalid();
  for (const value of data.files) {
    const file = controlWireRecord(value, ['canonicalRelativePath', 'contentRef', 'contentDigest', 'sizeBytes']);
    const path = decodeLocalModelPath(file.canonicalRelativePath), ref = controlWireRef(file.contentRef);
    const segments = path.split('/');
    if (Buffer.compare(Buffer.from(previous), Buffer.from(path)) >= 0 ||
        segments.some((_segment, index) => index > 0 && paths.has(segments.slice(0, index).join('/'))) ||
        objects.has(ref) || controlWireRef(file.contentDigest) !== ref) invalid();
    controlWireInteger(file.sizeBytes, 1); previous = path; paths.add(path); objects.add(ref);
  }
  if (localModelManifestDigest(data as LocalModelManifestV1) !== data.modelManifestDigest) invalid();
  return immutableSnapshot(data) as LocalModelManifestV1;
}
export function decodeLocalModelObjectClosure(value: unknown, manifest: LocalModelManifestV1): LocalModelObjectClosureV1 {
  const source = decodeLocalModelManifest(manifest);
  const data = object(value, ['schemaVersion', 'format', 'stateRootIdentityRef', 'stateRootIdentityDigest', 'objectStoreRootRelativePath',
    'modelManifestRef', 'modelManifestDigest', 'objects', 'objectCount', 'totalBytes', 'closureDigest']);
  header(data, 'cliq-local-model-object-closure-v1');
  refs(data, ['stateRootIdentityRef', 'stateRootIdentityDigest', 'modelManifestRef', 'modelManifestDigest']);
  if (data.objectStoreRootRelativePath !== 'local-models/objects' || data.modelManifestRef !== canonicalSha256(source) ||
      data.modelManifestDigest !== source.modelManifestDigest || !Array.isArray(data.objects) || data.objects.length !== source.files.length + 3 ||
      data.objectCount !== data.objects.length) invalid();
  const expected: Array<{ kind: string; logicalPath: string; ref: string; size?: number }> = [
    { kind: 'model_manifest', logicalPath: 'model-manifest.json', ref: canonicalSha256(source), size: canonicalJsonBytes(source).byteLength },
    { kind: 'model_signature', logicalPath: 'model-signature', ref: source.signatureRef, size: 64 },
    { kind: 'tokenizer', logicalPath: 'tokenizer', ref: source.tokenizerRef },
    ...source.files.map(file => ({ kind: 'model_file', logicalPath: file.canonicalRelativePath, ref: file.contentRef, size: file.sizeBytes }))
  ];
  let total = 0; const seen = new Set<string>();
  for (const [index, value] of data.objects.entries()) {
    const entry = controlWireRecord(value, ['kind', 'logicalPath', 'artifactRef', 'artifactDigest', 'sizeBytes']);
    const wanted = expected[index]!, size = controlWireInteger(entry.sizeBytes, 1), ref = controlWireRef(entry.artifactRef);
    if (entry.kind !== wanted.kind || entry.logicalPath !== wanted.logicalPath || ref !== wanted.ref || entry.artifactDigest !== ref ||
        wanted.size !== undefined && size !== wanted.size || seen.has(ref)) invalid();
    seen.add(ref); total += size; if (!Number.isSafeInteger(total)) invalid();
  }
  if (controlWireInteger(data.totalBytes, 1) !== total) invalid(); digest(data, 'closureDigest');
  return immutableSnapshot(data) as LocalModelObjectClosureV1;
}
const RESOURCE_RANGES: Readonly<Record<keyof SandboxResourceSpec, readonly [number, number]>> = {
  maxProcesses: [1, 1024], memoryBytes: [268435456, 34359738368], cpuQuotaMicrosPerSecond: [10000, 1600000], maxOpenFiles: [64, 8192],
  maxSingleFileBytes: [1048576, 17179869184], maxGenerationBytes: [268435456, 107374182400], maxInvocationOutputBytes: [65536, 67108864],
  maxIpcFrameBytes: [16777216, 16777216], maxQueuedIpcBytes: [67108864, 67108864]
};
function resources(value: unknown): void {
  const data = controlWireRecord(value, Object.keys(RESOURCE_RANGES));
  for (const [key, range] of Object.entries(RESOURCE_RANGES)) controlWireInteger(data[key], range[0], range[1]);
}
export function localServiceSpecCoreDigest(value: Omit<LocalInferenceServiceSpecV1,
  'serviceId' | 'createdAt' | 'serviceSpecCoreDigest' | 'serviceSpecDigest'> | LocalInferenceServiceSpecV1): string {
  const { serviceId: _id, createdAt: _time, serviceSpecCoreDigest: _core, serviceSpecDigest: _digest, ...core } = value as LocalInferenceServiceSpecV1;
  return canonicalSha256(core);
}
export function decodeLocalInferenceServiceSpec(value: unknown): LocalInferenceServiceSpecV1 {
  const data = object(value, ['schemaVersion', 'format', 'serviceId', 'ownerPrincipalId', 'runtimeBundleRef', 'runtimeBundleManifestDigest',
    'executableId', 'executableVersion', 'executableDigest', 'modelManifestRef', 'modelManifestDigest', 'endpoint', 'backend',
    'sandboxProfileRef', 'sandboxProfileDigest', 'resources', 'createdAt', 'serviceSpecCoreDigest', 'serviceSpecDigest']);
  header(data, 'cliq-local-inference-service-v1'); decodeLocalIdentity(data.serviceId); text(data.ownerPrincipalId); text(data.executableVersion);
  if (data.executableId !== 'ollama_local_inference' || !['linux_namespace', 'macos_vm'].includes(data.backend as string)) invalid();
  refs(data, ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'executableDigest', 'modelManifestRef', 'modelManifestDigest',
    'sandboxProfileRef', 'sandboxProfileDigest', 'serviceSpecCoreDigest']);
  const endpoint = controlWireRecord(data.endpoint, ['scheme', 'host', 'port']);
  if (endpoint.scheme !== 'http' || endpoint.host !== '127.0.0.1' && endpoint.host !== '[::1]') invalid();
  controlWireInteger(endpoint.port, 1, 65535); resources(data.resources); time(data.createdAt);
  if (localServiceSpecCoreDigest(data as LocalInferenceServiceSpecV1) !== data.serviceSpecCoreDigest) invalid();
  digest(data, 'serviceSpecDigest'); return immutableSnapshot(data) as LocalInferenceServiceSpecV1;
}
export function decodeLocalModelRegistration(value: unknown): LocalModelRegistrationV1 {
  const state = (value as { state?: unknown } | null)?.state;
  const data = object(value, ['schemaVersion', 'format', 'ownerPrincipalId', 'provider', 'model', 'registryRevision', 'serviceId',
    'serviceSpec', 'expectedServiceSpecRef', 'modelManifest', 'expectedModelManifestRef', 'objectClosure', 'expectedObjectClosureRef',
    'createdAt', 'state', 'registrationDigest', ...(state === 'retired' ? ['retiredAt'] : [])]);
  header(data, 'cliq-local-model-registration-v1'); text(data.ownerPrincipalId); text(data.model); controlWireInteger(data.registryRevision, 1);
  if (data.provider !== 'ollama' || state !== 'active' && state !== 'retired') invalid();
  const manifest = decodeLocalModelManifest(data.modelManifest), service = decodeLocalInferenceServiceSpec(data.serviceSpec),
    closure = decodeLocalModelObjectClosure(data.objectClosure, manifest);
  if (data.model !== manifest.model || data.ownerPrincipalId !== service.ownerPrincipalId || service.serviceId !== data.serviceId ||
      service.serviceId !== identityHash(data.ownerPrincipalId, 'ollama', data.model, service.serviceSpecCoreDigest) ||
      data.expectedServiceSpecRef !== canonicalSha256(service) || data.expectedModelManifestRef !== canonicalSha256(manifest) ||
      data.expectedObjectClosureRef !== canonicalSha256(closure) || service.modelManifestRef !== data.expectedModelManifestRef ||
      service.modelManifestDigest !== manifest.modelManifestDigest || closure.modelManifestRef !== data.expectedModelManifestRef ||
      time(data.createdAt) < service.createdAt) invalid();
  if (state === 'retired' && time(data.retiredAt) < (data.createdAt as string)) invalid();
  digest(data, 'registrationDigest'); return immutableSnapshot(data) as LocalModelRegistrationV1;
}
export function decodeLocalModelRegistryHead(value: unknown): LocalModelRegistryHeadV1 {
  const transition = (value as { transition?: unknown } | null)?.transition;
  if (!['initial', 'replace', 'retire', 'reenroll'].includes(transition as string)) invalid();
  const data = object(value, ['schemaVersion', 'format', 'ownerPrincipalId', 'provider', 'model', 'headRevision', 'committedAt',
    'headDigest', 'transition', 'state', ...(transition !== 'initial' ? ['predecessorHeadRef', 'predecessorHeadDigest'] : []),
    ...(transition !== 'retire' ? ['activeRegistrationRef', 'activeRegistrationDigest'] : []),
    ...(transition === 'retire' || transition === 'replace' ? ['retiredRegistrationRef', 'retiredRegistrationDigest'] : [])]);
  header(data, 'cliq-local-model-registry-head-v1'); text(data.ownerPrincipalId); text(data.model); time(data.committedAt);
  const revision = controlWireInteger(data.headRevision, 1);
  if (data.provider !== 'ollama' || data.state !== (transition === 'retire' ? 'retired' : 'active') ||
      (transition === 'initial' ? revision !== 1 : revision <= 1)) invalid();
  for (const key of Object.keys(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(data[key]);
  digest(data, 'headDigest'); return immutableSnapshot(data) as LocalModelRegistryHeadV1;
}
export function decodeLocalInferenceParticipant(value: unknown): LocalInferenceActivationParticipantV1 {
  const kind = (value as { kind?: unknown } | null)?.kind;
  if (kind !== 'run_submission' && kind !== 'run_model_frontier') invalid();
  const data = object(value, kind === 'run_submission' ? ['kind', 'requestId', 'requestDigest', 'runSubmitRequestRef',
    'channelIdentityRef', 'channelIdentityDigest', 'admissionKey', 'admissionIntentDigest', 'joinedAt'] :
    ['kind', 'runId', 'runRevisionAtJoin', 'frontierRef', 'joinedAt']);
  time(data.joinedAt);
  if (kind === 'run_submission') {
    assertRequestId(controlWireText(data.requestId));
    refs(data, ['requestDigest', 'runSubmitRequestRef', 'channelIdentityRef', 'channelIdentityDigest', 'admissionIntentDigest']);
    if (!/^[A-Za-z0-9_-]{22,128}$/u.test(controlWireText(data.admissionKey, 128, 22))) invalid();
  } else { text(data.runId); controlWireInteger(data.runRevisionAtJoin, 1); controlWireRef(data.frontierRef); }
  return immutableSnapshot(data) as LocalInferenceActivationParticipantV1;
}
export function localInferenceParticipantKey(value: LocalInferenceActivationParticipantV1): string {
  const data = decodeLocalInferenceParticipant(value);
  return canonicalJsonBytes(data.kind === 'run_submission' ? [data.kind, data.requestId] : [data.kind, data.runId, data.frontierRef]).toString('utf8');
}
export function localInferenceCycleId(input: Readonly<{ ownerPrincipalId: string; serviceId: string; serviceSpecDigest: string; cycleOrdinal: number }>): string {
  text(input.ownerPrincipalId); decodeLocalIdentity(input.serviceId); controlWireRef(input.serviceSpecDigest); controlWireInteger(input.cycleOrdinal, 1);
  return Buffer.from(canonicalSha256({ ownerPrincipalId: input.ownerPrincipalId, serviceId: input.serviceId,
    serviceSpecDigest: input.serviceSpecDigest, cycleOrdinal: input.cycleOrdinal }), 'hex').toString('base64url');
}
export function localInferenceLaunchId(cycleId: string, attempt: 1 | 2): string {
  decodeLocalIdentity(cycleId); controlWireInteger(attempt, 1, 2);
  return identityHash('cliq-local-inference-launch-v1', cycleId, attempt);
}
const CYCLE_FIELDS = ['schemaVersion', 'activationCycleId', 'ownerPrincipalId', 'serviceId', 'serviceSpecRef', 'serviceSpecDigest',
  'localModelRegistrationRef', 'localModelRegistrationDigest', 'cycleOrdinal', 'participants', 'rowVersion', 'createdAt', 'phase', 'activationAttempt', 'launchIds', 'cycleDigest'];
export function decodeLocalInferenceCycle(value: unknown): LocalInferenceActivationCycleV1 {
  const phase = (value as { phase?: unknown } | null)?.phase;
  if (!['starting_launch', 'retry_wait', 'active', 'failed'].includes(phase as string)) invalid();
  const data = object(value, [...CYCLE_FIELDS,
    ...(phase === 'starting_launch' || phase === 'active' ? ['currentLaunchId'] : []),
    ...(phase === 'retry_wait' ? ['retryNotBeforeAt'] : []), ...(phase === 'active' ? ['boundaryEvidenceRef', 'finishedAt'] : []),
    ...(phase === 'failed' ? ['failureDetailRef', 'finishedAt'] : [])]);
  header(data); text(data.ownerPrincipalId); decodeLocalIdentity(data.serviceId);
  refs(data, ['localModelRegistrationRef', 'localModelRegistrationDigest', 'serviceSpecRef', 'serviceSpecDigest']);
  controlWireInteger(data.cycleOrdinal, 1); controlWireInteger(data.rowVersion, 1); const at = time(data.createdAt), attempt = controlWireInteger(data.activationAttempt, 1, 2);
  if (data.activationCycleId !== localInferenceCycleId(data as Parameters<typeof localInferenceCycleId>[0]) ||
      !Array.isArray(data.participants) || data.participants.length < 1 || data.participants.length > LOCAL_INFERENCE_PARTICIPANTS ||
      !Array.isArray(data.launchIds) || data.launchIds.length !== attempt) invalid();
  const seen = new Set<string>(); let joined = at;
  for (const value of data.participants) {
    const participant = decodeLocalInferenceParticipant(value), key = localInferenceParticipantKey(participant);
    if (seen.has(key) || participant.joinedAt < joined) invalid(); seen.add(key); joined = participant.joinedAt;
  }
  data.launchIds.forEach((id, index) => { if (id !== localInferenceLaunchId(data.activationCycleId as string, (index + 1) as 1 | 2)) invalid(); });
  if ((phase === 'starting_launch' || phase === 'active') && data.currentLaunchId !== data.launchIds.at(-1)) invalid();
  if (phase === 'retry_wait' && (attempt !== 1 || time(data.retryNotBeforeAt) < at)) invalid();
  if (phase === 'active' || phase === 'failed') {
    if (time(data.finishedAt) < joined) invalid(); controlWireRef(data[phase === 'active' ? 'boundaryEvidenceRef' : 'failureDetailRef']);
  }
  digest(data, 'cycleDigest'); return immutableSnapshot(data) as LocalInferenceActivationCycleV1;
}
const LAUNCH_FIELDS = ['schemaVersion', 'serviceId', 'launchId', 'ownerPrincipalId', 'serviceSpecRef', 'serviceSpecDigest', 'supervisorInstanceId',
  'activationCycleId', 'activationAttempt', 'activationNonceDigest', 'containmentPlanRef', 'sandboxLaunchSpecRef', 'nativeInputRef', 'rowVersion', 'leaseVersion',
  'createdAt', 'activationDeadlineAt', 'phase'];
export function decodeLocalInferenceLaunch(value: unknown): LocalInferenceServiceLaunchV1 {
  const record = value as { phase?: unknown; retirementKind?: unknown } | null, phase = record?.phase;
  if (!['reserved', 'preactivated', 'active', 'revoking', 'retired'].includes(phase as string)) invalid();
  const death = phase === 'retired' && record?.retirementKind === 'death';
  const data = object(value, [...LAUNCH_FIELDS,
    ...(phase === 'preactivated' || phase === 'active' || phase === 'revoking' || death ? ['processContainmentRef'] : []),
    ...(phase === 'active' || phase === 'revoking' ? ['boundaryEvidenceRef'] : []), ...(phase === 'active' ? ['leaseExpiresAt'] : []),
    ...(phase === 'revoking' || death ? ['quiesceId'] : []),
    ...(phase === 'retired' ? ['retirementKind', 'retirementEvidenceRef', 'retiredAt'] : [])], death ? ['boundaryEvidenceRef'] : []);
  header(data); for (const key of ['ownerPrincipalId', 'supervisorInstanceId']) text(data[key]);
  decodeLocalIdentity(data.serviceId); decodeLocalIdentity(data.activationCycleId);
  const attempt = controlWireInteger(data.activationAttempt, 1, 2), version = controlWireInteger(data.rowVersion, 1), lease = controlWireInteger(data.leaseVersion);
  if (data.launchId !== localInferenceLaunchId(data.activationCycleId as string, attempt as 1 | 2)) invalid();
  refs(data, ['serviceSpecRef', 'serviceSpecDigest', 'activationNonceDigest', 'containmentPlanRef', 'sandboxLaunchSpecRef', 'nativeInputRef']);
  const at = time(data.createdAt), deadline = time(data.activationDeadlineAt);
  if (parseCanonicalTime(deadline) - parseCanonicalTime(at) !== LOCAL_INFERENCE_ACTIVATION_MS) invalid();
  if (phase === 'reserved' ? version !== 1 || lease !== 0 : version < 2) invalid();
  if (phase === 'active' && (lease < 1 || time(data.leaseExpiresAt) <= at)) invalid();
  if ((phase === 'reserved' || phase === 'preactivated') && lease !== 0) invalid();
  if (phase === 'retired' && (data.retirementKind !== 'death' && data.retirementKind !== 'no_spawn' || time(data.retiredAt) < at)) invalid();
  if (phase === 'retired' && data.retirementKind === 'no_spawn' && (lease !== 0 || version !== 2)) invalid();
  for (const key of ['processContainmentRef', 'boundaryEvidenceRef', 'retirementEvidenceRef']) if (Object.hasOwn(data, key)) controlWireRef(data[key]);
  if (Object.hasOwn(data, 'quiesceId')) text(data.quiesceId);
  return immutableSnapshot(data) as LocalInferenceServiceLaunchV1;
}
export function decodeLocalInferenceFailure(value: unknown): LocalInferenceActivationFailureV1 {
  const data = object(value, ['schemaVersion', 'activationCycleId', 'ownerPrincipalId', 'serviceId', 'serviceSpecRef', 'serviceSpecDigest',
    'finalAttempt', 'reason', 'launchIds', 'evidenceRefs', 'observedAt', 'failureDigest']);
  header(data); text(data.ownerPrincipalId); decodeLocalIdentity(data.activationCycleId); decodeLocalIdentity(data.serviceId);
  refs(data, ['serviceSpecRef', 'serviceSpecDigest']); const attempt = controlWireInteger(data.finalAttempt, 1, 2);
  if (!['activation_timeout', 'sandbox_launch_failed', 'health_mismatch', 'capability_mismatch',
    'containment_unprovable', 'activation_cancelled_for_migration'].includes(data.reason as string) ||
      !Array.isArray(data.launchIds) || data.launchIds.length !== attempt || !Array.isArray(data.evidenceRefs) ||
      data.evidenceRefs.length < 1 || data.evidenceRefs.length > 4 || new Set(data.evidenceRefs).size !== data.evidenceRefs.length) invalid();
  data.launchIds.forEach((id, index) => { if (id !== localInferenceLaunchId(data.activationCycleId as string, (index + 1) as 1 | 2)) invalid(); });
  data.evidenceRefs.forEach(controlWireRef); time(data.observedAt); digest(data, 'failureDigest');
  return immutableSnapshot(data) as LocalInferenceActivationFailureV1;
}

/** An unresolved attempt may be positively retired later. Historical
 * failure still names the original input, never the successor's proof. */
export function localInferenceFailureSources(cycle: LocalInferenceActivationCycleV1, failure: LocalInferenceActivationFailureV1,
  launches: readonly LocalInferenceServiceLaunchV1[]): readonly Readonly<{ ref: string;
    purpose: 'local_inference_native_input' | 'process_containment_no_spawn' | 'process_containment_death' }>[] {
  if ((cycle.phase !== 'starting_launch' && cycle.phase !== 'failed') || failure.activationCycleId !== cycle.activationCycleId ||
      failure.ownerPrincipalId !== cycle.ownerPrincipalId || failure.serviceId !== cycle.serviceId || failure.serviceSpecRef !== cycle.serviceSpecRef ||
      failure.serviceSpecDigest !== cycle.serviceSpecDigest || failure.finalAttempt !== cycle.activationAttempt ||
      failure.observedAt < cycle.participants.at(-1)!.joinedAt || cycle.phase === 'failed' &&
        (failure.observedAt > cycle.finishedAt || canonicalSha256(failure) !== cycle.failureDetailRef) ||
      launches.length !== cycle.launchIds.length || failure.launchIds.some((id, index) => id !== cycle.launchIds[index]))
    invalid();
  const first = launches[0], second = launches[1];
  if (second && (first?.phase !== 'retired' ||
      parseCanonicalTime(second.createdAt) - parseCanonicalTime(first.retiredAt) < LOCAL_INFERENCE_RETRY_MS)) invalid();
  const sources = launches.map((launch, index) => {
    if (launch.launchId !== cycle.launchIds[index] || launch.activationAttempt !== index + 1 || launch.activationCycleId !== cycle.activationCycleId ||
        launch.ownerPrincipalId !== cycle.ownerPrincipalId || launch.serviceId !== cycle.serviceId || launch.serviceSpecRef !== cycle.serviceSpecRef ||
        launch.serviceSpecDigest !== cycle.serviceSpecDigest || launch.createdAt > failure.observedAt)
      invalid();
    if (index === launches.length - 1 && failure.reason === 'containment_unprovable') {
      if (launch.phase === 'retired' && launch.retiredAt < failure.observedAt) invalid();
      return { ref: launch.nativeInputRef, purpose: 'local_inference_native_input' as const };
    }
    if (launch.phase !== 'retired' || launch.retiredAt > failure.observedAt || cycle.activationAttempt === 1) invalid();
    return { ref: launch.retirementEvidenceRef, purpose: launch.retirementKind === 'no_spawn'
      ? 'process_containment_no_spawn' as const : 'process_containment_death' as const };
  });
  if (sources.length !== failure.evidenceRefs.length || sources.some((item, index) => item.ref !== failure.evidenceRefs[index])) invalid();
  return sources;
}
export function localStableServiceIdentity(input: Readonly<{ service: LocalInferenceServiceSpecV1; serviceSpecRef: string }>): string {
  const service = decodeLocalInferenceServiceSpec(input.service);
  if (controlWireRef(input.serviceSpecRef) !== canonicalSha256(service)) invalid();
  return canonicalSha256({ ownerPrincipalId: service.ownerPrincipalId, serviceId: service.serviceId, serviceSpecRef: input.serviceSpecRef,
    serviceSpecDigest: service.serviceSpecDigest, runtimeBundleRef: service.runtimeBundleRef, runtimeBundleManifestDigest: service.runtimeBundleManifestDigest,
    executableId: service.executableId, executableDigest: service.executableDigest, modelManifestRef: service.modelManifestRef,
    modelManifestDigest: service.modelManifestDigest, backend: service.backend, externalNetworkEgress: 'denied', loopbackOnly: true });
}
export function decodeLocalInferenceBoundary(value: unknown): LocalInferenceBoundaryEvidenceV1 {
  const data = object(value, ['schemaVersion', 'format', 'ownerPrincipalId', 'serviceId', 'serviceSpecRef', 'serviceSpecDigest', 'serviceLaunchId',
    'runtimeBundleRef', 'runtimeBundleManifestDigest', 'executableId', 'executableDigest', 'modelManifestRef', 'modelManifestDigest', 'processContainmentRef',
    'containmentPlanRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'backend', 'externalNetworkEgress', 'loopbackOnly', 'stableServiceIdentityDigest',
    'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'validThrough', 'evidenceDigest']);
  header(data, 'cliq-local-inference-boundary-v1'); text(data.ownerPrincipalId); decodeLocalIdentity(data.serviceId); decodeLocalIdentity(data.serviceLaunchId);
  text(data.inspectorSupervisorInstanceId);
  refs(data, ['serviceSpecRef', 'serviceSpecDigest', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'executableDigest', 'modelManifestRef', 'modelManifestDigest',
    'processContainmentRef', 'containmentPlanRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'stableServiceIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest']);
  if (data.executableId !== 'ollama_local_inference' || !['linux_namespace', 'macos_vm'].includes(data.backend as string) ||
      data.externalNetworkEgress !== 'denied' || data.loopbackOnly !== true || time(data.observedAt) >= time(data.validThrough)) invalid();
  const projection = { ownerPrincipalId: data.ownerPrincipalId, serviceId: data.serviceId, serviceSpecRef: data.serviceSpecRef,
    serviceSpecDigest: data.serviceSpecDigest, runtimeBundleRef: data.runtimeBundleRef, runtimeBundleManifestDigest: data.runtimeBundleManifestDigest,
    executableId: data.executableId, executableDigest: data.executableDigest, modelManifestRef: data.modelManifestRef,
    modelManifestDigest: data.modelManifestDigest, backend: data.backend, externalNetworkEgress: 'denied', loopbackOnly: true };
  if (canonicalSha256(projection) !== data.stableServiceIdentityDigest) invalid();
  digest(data, 'evidenceDigest'); return immutableSnapshot(data) as LocalInferenceBoundaryEvidenceV1;
}
