import { types } from 'node:util';
import { canonicalSha256 } from './canonical.js';
import { assertArtifactRef, assertRequestId, digestOmitting, normalizeBoundedText, parseCanonicalTime } from './identity.js';
import type { ArtifactRef } from './types.js';

export type DependencyAdapter = 'npm-ci-v1' | 'pnpm-frozen-v1' | 'yarn-immutable-v1';
export type DependencyGypConditionV1 = { kind: 'absent' } | { kind: 'present'; contentDigest: string };
export type DependencyGypSourceV1 = { kind: 'absent' } | { kind: 'present'; contentRef: ArtifactRef; contentDigest: string };
/** Consent conditions only. A ref in this value never proves capture, an
 * absent path, a sealed generation or permission to launch an interpreter. */
export type DependencyScriptConditionsV1 = {
  profile: 'npm-ci-v1'; lockfilePath: 'package-lock.json'; lockfileDigest: string;
  packageManifestDigest: string; bindingGyp: DependencyGypConditionV1;
  source: { sourceManifestRef: ArtifactRef; sourceManifestDigest: string; sourceRole: 'base' | 'result';
    projectedEntriesRef: ArtifactRef; projectedTreeDigest: string;
    sourceProjectionRef: ArtifactRef; sourceProjectionDigest: string;
    workspaceEntriesRef: ArtifactRef; workspaceTreeDigest: string; scriptInputTreeDigest: string;
    privateGit: { kind: 'absent' } | { kind: 'present'; stateRef: ArtifactRef } };
  execution: { runtimeBundleRef: ArtifactRef; runtimeBundleManifestDigest: string;
    guestToolchainManifestRef: ArtifactRef; guestToolchainManifestDigest: string;
    nodeExecutionPath: '/usr/bin/node'; nodeExecutableDigest: string;
    adapterCodeRef: ArtifactRef; npmDataRef: ArtifactRef;
    registryTargetsDigest: string; environmentDigest: string };
};
export type DependencyEndpointV1 = {
  endpointRegistrationRef: ArtifactRef; endpointIdentityDigest: string; tlsPolicyDigest: string;
};
export type DependencyPackageDescriptorV1 = Readonly<{ packageName: string; packageVersion: string; endpointRegistrationRef: ArtifactRef;
  canonicalPackagePath: string; integrityAlgorithm: 'sha256' | 'sha512'; integrityDigest: string }>;
export type DependencyPolicy = {
  schemaVersion: 1; mode: 'none' | 'locked_node'; allowedAdapters: DependencyAdapter[];
  registryEndpoints: DependencyEndpointV1[]; credentialGrantRefs: ArtifactRef[];
  installScriptsPolicy: 'deny' | 'exact_lockfile_grant'; installScriptsGrantRef?: ArtifactRef;
  maxPackages: number; maxDownloadBytes: number;
};
type PlanBase = {
  schemaVersion: 1; format: 'cliq-dependency-acquisition-plan-v1'; ecosystem: 'node';
  guestToolchainManifestRef: ArtifactRef;
  packageManifest: { canonicalRootRelativePath: 'package.json'; contentRef: ArtifactRef; contentDigest: string };
  bindingGyp: DependencyGypSourceV1;
  lockfileRef: ArtifactRef; lockfileDigest: string; registryEndpoints: DependencyEndpointV1[];
  credentialGrantRefs: ArtifactRef[]; allowInstallScripts: boolean; maxPackages: number; maxDownloadBytes: number;
  packageCount: number; descriptorSequenceDigest: string; packageDescriptorBytes: number;
  planDigest: string;
};
export type DependencyAcquisitionPlan = PlanBase & (
  | { adapter: 'npm-ci-v1'; lockfilePath: 'package-lock.json' }
  | { adapter: 'pnpm-frozen-v1'; lockfilePath: 'pnpm-lock.yaml' }
  | { adapter: 'yarn-immutable-v1'; lockfilePath: 'yarn.lock' }
);
export type DependencyInstallScriptsAuthorizationTemplateV1 = {
  schemaVersion: 1; format: 'cliq-dependency-install-scripts-authorization-v1'; runId: string; ownerPrincipalId: string;
  workspaceIdentityDigest: string;
  provenance:
    | { kind: 'run_admission'; sourceAuthorizationGrantId: string; sourceConsumptionReceiptRef: ArtifactRef }
    | { kind: 'candidate_approval'; waitingSubjectRef: ArtifactRef; decisionRef: ArtifactRef; responseRef: ArtifactRef;
        requestId: string; requestDigest: string; candidateOrdinal: number; dependencyPlanRef: ArtifactRef; resultSourceRef: ArtifactRef };
  scriptConditions: DependencyScriptConditionsV1;
  guestToolchainManifestRef: ArtifactRef; allowedAdapters: DependencyAdapter[];
  lockfilePath: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock'; lockfileRef: ArtifactRef; lockfileDigest: string;
  packageManifestRef: ArtifactRef; packageManifestDigest: string; bindingGyp: DependencyGypSourceV1;
  registryTargetsDigest: string; maxCandidateGenerations: number; maxDispatchedAttemptsPerPlan: 1;
  expiresAt: string; templateDigest: string;
};
export type PackageCacheFetchAttemptV1 = {
  attempt: 1 | 2 | 3; outcome: 'transport_failed' | 'http_error' | 'integrity_mismatch' | 'completed';
  httpStatus?: number; receivedBytes: number; observationDigest: string;
};
export type PackageCacheEntryV1 = {
  packageName: string; packageVersion: string; endpointRegistrationRef: ArtifactRef; canonicalPackagePath: string;
  integrityAlgorithm: 'sha256' | 'sha512'; integrityDigest: string; blobRef: ArtifactRef; blobDigest: string;
  blobBytes: number; fetchAttempts: PackageCacheFetchAttemptV1[];
};
export type PackageCacheManifestV1 = {
  schemaVersion: 1; format: 'cliq-package-cache-manifest-v1'; runId: string; resultSourceRef: ArtifactRef;
  dependencyPlanRef: ArtifactRef; lockfileRef: ArtifactRef; lockfileDigest: string; entries: PackageCacheEntryV1[];
  packageCount: number; totalTransferredBytes: number; manifestDigest: string; createdAt: string;
};
export type DependencyReadyItem = {
  schemaVersion: 1; kind: 'dependency_ready'; itemId: string; runId: string; planRef: ArtifactRef;
  readyCheckpointId: string; installedTreeDigest: string; createdAt: string;
} & (
  | { origin: 'acquired'; opId: string; attempt: number; packageCacheManifestRef: ArtifactRef }
  | { origin: 'inherited_parent_ready'; parentRunId: string; parentReadyItemRef: ArtifactRef; parentReadyCheckpointId: string;
      parentReadyWorkspaceStateRef: ArtifactRef; childAdmissionRequestRef: ArtifactRef;
      childPreparation: { workerLaunchId: string; snapshotEvidenceRef: ArtifactRef; retirementEvidenceRef: ArtifactRef } }
);
/** A positively received failure is distinct from UNKNOWN and from readiness.
 * Its receipt owns the real post-effect Checkpoint, never another dispatch. */
export type DependencyFailureItem = {
  schemaVersion: 1; kind: 'dependency_failure'; itemId: string; runId: string; opId: string; attempt: number;
  planRef: ArtifactRef; receiptRef: ArtifactRef; checkpointId: string;
  failureKind: 'process_failed' | 'source_integrity' | 'acquisition_failed'; createdAt: string;
};
export function decodeDependencyFailureItem(value: unknown): DependencyFailureItem {
  const data = object(value, ['schemaVersion', 'kind', 'itemId', 'runId', 'opId', 'attempt', 'planRef', 'receiptRef', 'checkpointId', 'failureKind', 'createdAt']);
  if (data.schemaVersion !== 1 || data.kind !== 'dependency_failure' || !['process_failed', 'source_integrity', 'acquisition_failed'].includes(String(data.failureKind))) fail();
  for (const key of ['itemId', 'runId', 'opId', 'checkpointId']) text(data[key]);
  integer(data.attempt, 0, 1); ref(data.planRef); ref(data.receiptRef); parseCanonicalTime(data.createdAt as string);
  return data as DependencyFailureItem;
}

export const DEPENDENCY_LIMITS = Object.freeze({ defaultPackages: 50_000, maxPackages: 200_000,
  defaultDownloadBytes: 5 * 1_073_741_824, maxDownloadBytes: 20 * 1_073_741_824 });
const adapters = ['npm-ci-v1', 'pnpm-frozen-v1', 'yarn-immutable-v1'] as const;
const paths = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;
function fail(): never { throw new TypeError('dependency data violates its closed contract'); }
const compare = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));
function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 4096) !== value) fail();
}
function ref(value: unknown): asserts value is string { text(value); assertArtifactRef(value); }
function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail();
}
/** Pure data only: reject proxies/accessors before invoking caller code. */
function object(value: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value)) fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) fail();
  const properties = Object.getOwnPropertyDescriptors(value), names = Reflect.ownKeys(properties);
  if (names.some(key => typeof key !== 'string' || !keys.includes(key) && !optional.includes(key)) || keys.some(key => !Object.hasOwn(properties, key))) fail();
  const copy: Record<string, unknown> = Object.create(null);
  for (const key of names as string[]) {
    const property = properties[key]!;
    if (!('value' in property) || !property.enumerable) fail();
    copy[key] = property.value;
  }
  return copy;
}
function array(value: unknown, minimum: number, maximum: number): unknown[] {
  if (value === null || typeof value !== 'object' || types.isProxy(value) || !Array.isArray(value) || value.length < minimum || value.length > maximum) fail();
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(properties).some(key => key !== 'length' && (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= value.length))) fail();
  const result: unknown[] = [];
  for (let index = 0; index < value.length; index++) {
    const property = properties[String(index)];
    if (!property || !('value' in property) || !property.enumerable) fail();
    result.push(property.value);
  }
  return result;
}
function sorted<T>(values: T[], key: (value: T) => string): T[] {
  for (let index = 1; index < values.length; index++) if (compare(key(values[index - 1]!), key(values[index]!)) >= 0) fail();
  return values;
}
function selectedAdapters(value: unknown): DependencyAdapter[] {
  return sorted(array(value, 0, 3).map(item => { if (!adapters.includes(item as DependencyAdapter)) fail(); return item as DependencyAdapter; }), item => item);
}
function endpoints(value: unknown): DependencyEndpointV1[] {
  return sorted(array(value, 0, 128).map(item => {
    const data = object(item, ['endpointRegistrationRef', 'endpointIdentityDigest', 'tlsPolicyDigest']);
    for (const field of ['endpointRegistrationRef', 'endpointIdentityDigest', 'tlsPolicyDigest']) ref(data[field]);
    return data as DependencyEndpointV1;
  }), item => item.endpointRegistrationRef);
}
function refs(value: unknown): string[] { return sorted(array(value, 0, 32).map(item => { ref(item); return item; }), item => item); }
function limits(data: Record<string, unknown>, none = false): void {
  integer(data.maxPackages, none ? 0 : 1, DEPENDENCY_LIMITS.maxPackages);
  integer(data.maxDownloadBytes, none ? 0 : 1, DEPENDENCY_LIMITS.maxDownloadBytes);
  if (none && (data.maxPackages !== 0 || data.maxDownloadBytes !== 0)) fail();
}
export function decodeDependencyGypSource(value: unknown): DependencyGypSourceV1 {
  const header = object(value, ['kind'], ['contentRef', 'contentDigest']);
  if (header.kind === 'absent') {
    if (Object.hasOwn(header, 'contentRef') || Object.hasOwn(header, 'contentDigest')) fail();
  } else if (header.kind === 'present') {
    ref(header.contentRef); ref(header.contentDigest);
    if (header.contentRef !== header.contentDigest) fail();
  } else fail();
  return header as DependencyGypSourceV1;
}
export function decodeDependencyGypCondition(value: unknown): DependencyGypConditionV1 {
  const data = object(value, ['kind'], ['contentDigest']);
  if (data.kind === 'present') ref(data.contentDigest);
  else if (data.kind !== 'absent' || Object.hasOwn(data, 'contentDigest')) fail();
  return data as DependencyGypConditionV1;
}
export function decodeDependencyScriptConditions(value: unknown): DependencyScriptConditionsV1 {
  const data = object(value, ['profile', 'lockfilePath', 'lockfileDigest', 'packageManifestDigest', 'bindingGyp', 'source', 'execution']);
  if (data.profile !== 'npm-ci-v1' || data.lockfilePath !== 'package-lock.json') fail();
  ref(data.lockfileDigest); ref(data.packageManifestDigest);
  data.bindingGyp = decodeDependencyGypCondition(data.bindingGyp);
  const source = object(data.source, ['sourceManifestRef', 'sourceManifestDigest', 'sourceRole', 'projectedEntriesRef', 'projectedTreeDigest', 'sourceProjectionRef', 'sourceProjectionDigest',
    'workspaceEntriesRef', 'workspaceTreeDigest', 'scriptInputTreeDigest', 'privateGit']);
  if (source.sourceRole !== 'base' && source.sourceRole !== 'result') fail();
  for (const key of ['sourceManifestRef', 'sourceManifestDigest', 'projectedEntriesRef', 'projectedTreeDigest', 'sourceProjectionRef', 'sourceProjectionDigest', 'workspaceEntriesRef', 'workspaceTreeDigest', 'scriptInputTreeDigest']) ref(source[key]);
  const git = object(source.privateGit, ['kind'], ['stateRef']);
  if (git.kind === 'present') ref(git.stateRef);
  else if (git.kind !== 'absent' || Object.hasOwn(git, 'stateRef')) fail();
  source.privateGit = git; data.source = source;
  const execution = object(data.execution, ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'guestToolchainManifestRef',
    'guestToolchainManifestDigest', 'nodeExecutionPath', 'nodeExecutableDigest', 'adapterCodeRef', 'npmDataRef', 'registryTargetsDigest', 'environmentDigest']);
  if (execution.nodeExecutionPath !== '/usr/bin/node') fail();
  for (const key of ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'guestToolchainManifestRef', 'guestToolchainManifestDigest',
    'nodeExecutableDigest', 'adapterCodeRef', 'npmDataRef', 'registryTargetsDigest', 'environmentDigest']) ref(execution[key]);
  data.execution = execution;
  return data as DependencyScriptConditionsV1;
}
export function decodeDependencyPolicy(value: unknown): DependencyPolicy {
  const data = object(value, ['schemaVersion', 'mode', 'allowedAdapters', 'registryEndpoints', 'credentialGrantRefs',
    'installScriptsPolicy', 'maxPackages', 'maxDownloadBytes'], ['installScriptsGrantRef']);
  if (data.schemaVersion !== 1 || data.mode !== 'none' && data.mode !== 'locked_node' ||
      data.installScriptsPolicy !== 'deny' && data.installScriptsPolicy !== 'exact_lockfile_grant') fail();
  data.allowedAdapters = selectedAdapters(data.allowedAdapters); data.registryEndpoints = endpoints(data.registryEndpoints);
  data.credentialGrantRefs = refs(data.credentialGrantRefs); limits(data, data.mode === 'none');
  if (data.mode === 'none' ? (data.allowedAdapters as unknown[]).length || (data.registryEndpoints as unknown[]).length ||
      (data.credentialGrantRefs as unknown[]).length || data.installScriptsPolicy !== 'deny' :
      !(data.allowedAdapters as unknown[]).length || !(data.registryEndpoints as unknown[]).length) fail();
  if (data.installScriptsPolicy === 'exact_lockfile_grant') ref(data.installScriptsGrantRef);
  else if (Object.hasOwn(data, 'installScriptsGrantRef')) fail();
  return data as DependencyPolicy;
}
export function decodeDependencyAcquisitionPlan(value: unknown): DependencyAcquisitionPlan {
  const data = object(value, ['schemaVersion', 'format', 'ecosystem', 'guestToolchainManifestRef', 'packageManifest',
    'lockfileRef', 'lockfileDigest', 'registryEndpoints', 'credentialGrantRefs', 'allowInstallScripts', 'maxPackages',
    'maxDownloadBytes', 'planDigest', 'adapter', 'lockfilePath', 'bindingGyp', 'packageCount', 'descriptorSequenceDigest', 'packageDescriptorBytes']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-acquisition-plan-v1' || data.ecosystem !== 'node' ||
      !adapters.includes(data.adapter as DependencyAdapter) || paths[adapters.indexOf(data.adapter as DependencyAdapter)] !== data.lockfilePath ||
      typeof data.allowInstallScripts !== 'boolean') fail();
  for (const field of ['guestToolchainManifestRef', 'lockfileRef', 'lockfileDigest', 'planDigest']) ref(data[field]);
  const manifest = object(data.packageManifest, ['canonicalRootRelativePath', 'contentRef', 'contentDigest']);
  if (manifest.canonicalRootRelativePath !== 'package.json') fail();
  ref(manifest.contentRef); ref(manifest.contentDigest);
  if (manifest.contentRef !== manifest.contentDigest || data.lockfileRef !== data.lockfileDigest) fail();
  data.packageManifest = manifest; data.registryEndpoints = endpoints(data.registryEndpoints); data.credentialGrantRefs = refs(data.credentialGrantRefs);
  data.bindingGyp = decodeDependencyGypSource(data.bindingGyp);
  if (!(data.registryEndpoints as unknown[]).length) fail();
  limits(data);
  integer(data.packageCount, 0, data.maxPackages as number); ref(data.descriptorSequenceDigest);
  integer(data.packageDescriptorBytes, 0, 67_108_864);
  if ((data.packageCount === 0) !== (data.packageDescriptorBytes === 0) || (data.packageDescriptorBytes as number) < (data.packageCount as number) * 4) fail();
  if (digestOmitting(data, 'planDigest') !== data.planDigest) fail();
  return data as DependencyAcquisitionPlan;
}
export function decodeDependencyInstallScriptsTemplate(value: unknown): DependencyInstallScriptsAuthorizationTemplateV1 {
  const data = object(value, ['schemaVersion', 'format', 'runId', 'ownerPrincipalId', 'workspaceIdentityDigest', 'provenance', 'scriptConditions',
    'guestToolchainManifestRef', 'allowedAdapters', 'lockfilePath', 'lockfileRef', 'lockfileDigest',
    'packageManifestRef', 'packageManifestDigest', 'bindingGyp', 'registryTargetsDigest', 'maxCandidateGenerations', 'maxDispatchedAttemptsPerPlan', 'expiresAt', 'templateDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-install-scripts-authorization-v1' ||
      data.maxDispatchedAttemptsPerPlan !== 1 || !paths.includes(data.lockfilePath as typeof paths[number])) fail();
  for (const field of ['runId', 'ownerPrincipalId']) text(data[field]);
  for (const field of ['workspaceIdentityDigest', 'guestToolchainManifestRef', 'lockfileRef', 'lockfileDigest',
    'packageManifestRef', 'packageManifestDigest', 'registryTargetsDigest', 'templateDigest']) ref(data[field]);
  const bindingGyp = decodeDependencyGypSource(data.bindingGyp); data.bindingGyp = bindingGyp;
  const conditions = decodeDependencyScriptConditions(data.scriptConditions); data.scriptConditions = conditions;
  if (conditions.lockfilePath !== data.lockfilePath || conditions.lockfileDigest !== data.lockfileDigest ||
      conditions.packageManifestDigest !== data.packageManifestDigest || conditions.execution.guestToolchainManifestRef !== data.guestToolchainManifestRef ||
      conditions.execution.registryTargetsDigest !== data.registryTargetsDigest ||
      canonicalSha256(conditions.bindingGyp) !== canonicalSha256(bindingGyp.kind === 'present'
        ? { kind: 'present', contentDigest: bindingGyp.contentDigest } : { kind: 'absent' })) fail();
  data.allowedAdapters = selectedAdapters(data.allowedAdapters);
  if (!(data.allowedAdapters as unknown[]).length || data.lockfileRef !== data.lockfileDigest || data.packageManifestRef !== data.packageManifestDigest) fail();
  integer(data.maxCandidateGenerations, 1); text(data.expiresAt); parseCanonicalTime(data.expiresAt);
  const header = object(data.provenance, ['kind'], ['sourceAuthorizationGrantId', 'sourceConsumptionReceiptRef', 'waitingSubjectRef', 'decisionRef', 'responseRef',
    'requestId', 'requestDigest', 'candidateOrdinal', 'dependencyPlanRef', 'resultSourceRef']);
  if (header.kind === 'run_admission') {
    const origin = object(header, ['kind', 'sourceAuthorizationGrantId', 'sourceConsumptionReceiptRef']);
    text(origin.sourceAuthorizationGrantId); ref(origin.sourceConsumptionReceiptRef); data.provenance = origin;
  } else if (header.kind === 'candidate_approval') {
    const origin = object(header, ['kind', 'waitingSubjectRef', 'decisionRef', 'responseRef', 'requestId', 'requestDigest', 'candidateOrdinal', 'dependencyPlanRef', 'resultSourceRef']);
    for (const field of ['waitingSubjectRef', 'decisionRef', 'responseRef', 'requestDigest', 'dependencyPlanRef', 'resultSourceRef']) ref(origin[field]);
    if (typeof origin.requestId !== 'string') fail(); assertRequestId(origin.requestId);
    integer(origin.candidateOrdinal, 0, data.maxCandidateGenerations - 1); data.provenance = origin;
  } else fail();
  if (digestOmitting(data, 'templateDigest') !== data.templateDigest) fail();
  return data as DependencyInstallScriptsAuthorizationTemplateV1;
}

export const dependencyRegistryTargetsDigest = (policy: Pick<DependencyPolicy, 'registryEndpoints' | 'credentialGrantRefs'>) =>
  canonicalSha256({ registryEndpoints: policy.registryEndpoints, credentialGrantRefs: policy.credentialGrantRefs });

/** Data only. Acquired history needs its real same-Run completed Journal;
 * inherited history instead needs the complete original parent ready/fork
 * graph and the child's own genuine preparing/seal. Neither decodes to an
 * execution grant or permits another install/script dispatch. */
export function decodeDependencyReadyItem(value: unknown): DependencyReadyItem {
  const common = ['schemaVersion', 'kind', 'itemId', 'runId', 'planRef', 'readyCheckpointId', 'installedTreeDigest', 'createdAt', 'origin'];
  const header = object(value, common, ['opId', 'attempt', 'packageCacheManifestRef', 'parentRunId', 'parentReadyItemRef',
    'parentReadyCheckpointId', 'parentReadyWorkspaceStateRef', 'childAdmissionRequestRef', 'childPreparation']);
  const data = object(header, [...common, ...(header.origin === 'acquired' ? ['opId', 'attempt', 'packageCacheManifestRef'] :
    ['parentRunId', 'parentReadyItemRef', 'parentReadyCheckpointId', 'parentReadyWorkspaceStateRef', 'childAdmissionRequestRef', 'childPreparation'])]);
  if (data.schemaVersion !== 1 || data.kind !== 'dependency_ready') fail();
  for (const key of ['itemId', 'runId', 'readyCheckpointId']) text(data[key]);
  for (const key of ['planRef', 'installedTreeDigest']) ref(data[key]);
  text(data.createdAt); parseCanonicalTime(data.createdAt);
  if (data.origin === 'acquired') {
    text(data.opId); integer(data.attempt, 0, 4); ref(data.packageCacheManifestRef);
  } else if (data.origin === 'inherited_parent_ready') {
    text(data.parentRunId); text(data.parentReadyCheckpointId);
    if (data.parentRunId === data.runId) fail();
    for (const key of ['parentReadyItemRef', 'parentReadyWorkspaceStateRef', 'childAdmissionRequestRef']) ref(data[key]);
    const preparing = object(data.childPreparation, ['workerLaunchId', 'snapshotEvidenceRef', 'retirementEvidenceRef']);
    text(preparing.workerLaunchId); ref(preparing.snapshotEvidenceRef); ref(preparing.retirementEvidenceRef); data.childPreparation = preparing;
  } else fail();
  return data as DependencyReadyItem;
}

export function packageCacheKey(value: Pick<PackageCacheEntryV1, 'packageName' | 'packageVersion' | 'endpointRegistrationRef' | 'canonicalPackagePath' | 'integrityAlgorithm' | 'integrityDigest'>): string {
  return [value.packageName, value.packageVersion, value.endpointRegistrationRef, value.canonicalPackagePath, value.integrityAlgorithm, value.integrityDigest].join('\0');
}
export function decodePackageCacheManifest(value: unknown): PackageCacheManifestV1 {
  const data = object(value, ['schemaVersion', 'format', 'runId', 'resultSourceRef', 'dependencyPlanRef', 'lockfileRef', 'lockfileDigest',
    'entries', 'packageCount', 'totalTransferredBytes', 'manifestDigest', 'createdAt']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-package-cache-manifest-v1') fail();
  text(data.runId); text(data.createdAt); parseCanonicalTime(data.createdAt);
  for (const field of ['resultSourceRef', 'dependencyPlanRef', 'lockfileRef', 'lockfileDigest', 'manifestDigest']) ref(data[field]);
  if (data.lockfileRef !== data.lockfileDigest) fail();
  let transferred = 0;
  data.entries = sorted(array(data.entries, 0, DEPENDENCY_LIMITS.maxPackages).map(value => {
    const entry = object(value, ['packageName', 'packageVersion', 'endpointRegistrationRef', 'canonicalPackagePath', 'integrityAlgorithm',
      'integrityDigest', 'blobRef', 'blobDigest', 'blobBytes', 'fetchAttempts']);
    text(entry.packageName); text(entry.packageVersion); text(entry.canonicalPackagePath); text(entry.integrityDigest);
    if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u.test(entry.packageName) ||
        !/^\/[A-Za-z0-9_~.@+/-]+$/u.test(entry.canonicalPackagePath) ||
        entry.canonicalPackagePath.slice(1).split('/').some(part => !part || part === '.' || part === '..') ||
        entry.integrityAlgorithm !== 'sha256' && entry.integrityAlgorithm !== 'sha512') fail();
    const decoded = Buffer.from(entry.integrityDigest, 'base64');
    if (decoded.toString('base64') !== entry.integrityDigest || decoded.length !== (entry.integrityAlgorithm === 'sha256' ? 32 : 64)) fail();
    for (const field of ['endpointRegistrationRef', 'blobRef', 'blobDigest']) ref(entry[field]);
    integer(entry.blobBytes, 1, 268_435_456);
    if (entry.blobRef !== entry.blobDigest) fail();
    const attempts = array(entry.fetchAttempts, 1, 3);
    entry.fetchAttempts = attempts.map((value, index) => {
      const attempt = object(value, ['attempt', 'outcome', 'receivedBytes', 'observationDigest'], ['httpStatus']);
      if (attempt.attempt !== index + 1 || !['transport_failed', 'http_error', 'integrity_mismatch', 'completed'].includes(attempt.outcome as string) ||
          (index === attempts.length - 1) !== (attempt.outcome === 'completed')) fail();
      integer(attempt.receivedBytes, 0, DEPENDENCY_LIMITS.maxDownloadBytes); ref(attempt.observationDigest);
      if (attempt.outcome === 'http_error') {
        integer(attempt.httpStatus, 100, 599);
      } else if (Object.hasOwn(attempt, 'httpStatus')) fail();
      if (attempt.outcome === 'completed' && attempt.receivedBytes !== entry.blobBytes) fail();
      transferred += attempt.receivedBytes;
      if (!Number.isSafeInteger(transferred) || transferred > DEPENDENCY_LIMITS.maxDownloadBytes) fail();
      return attempt as PackageCacheFetchAttemptV1;
    });
    return entry as PackageCacheEntryV1;
  }), packageCacheKey);
  integer(data.packageCount, 0, DEPENDENCY_LIMITS.maxPackages); integer(data.totalTransferredBytes, 0, DEPENDENCY_LIMITS.maxDownloadBytes);
  if (data.packageCount !== (data.entries as PackageCacheEntryV1[]).length || data.totalTransferredBytes !== transferred ||
      digestOmitting(data, 'manifestDigest') !== data.manifestDigest) fail();
  return data as PackageCacheManifestV1;
}
