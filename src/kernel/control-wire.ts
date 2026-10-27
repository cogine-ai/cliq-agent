import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from './canonical.js';
import { assertAdmissionKey, assertRequestId, normalizeAbsolutePath, normalizeBoundedText, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ControlResultV1, RunEvent, RunSnapshotV1, SessionSnapshotV1 } from './types.js';
import type { UserInputValue } from './user-input.js';
import { decodeCredentialAuthorityOperation, type CredentialAuthorityOperationV1 } from './credential-authority.js';
import { assertBoundedJsonValue, parseJsonStrict } from './json.js';
import { decodeWireRun, decodeWireSession, decodeWireCheckpoint, decodeWireEvent, decodeWireJournal,
  decodeWireArtifactDescriptor, decodeWireGrantSummary, decodeWireRuntimeBundleSummary, decodeWireRunItemReference, decodeWireSessionItem } from './control-wire-data.js';
import type { AuthorizationCreateRequest, AuthorizationRevokeRequest, SourceGitInspectionCreateRequest, SourceReadScopeCreateRequest, VerifierIdentityCreateRequest,
  DependencyInstallScriptsCreateRequest, DependencyInstallScriptsDecisionV1 } from './authorization.js';
import { decodeDependencyScriptConditions } from './dependency.js';
import { normalizeSourceReadScopePath } from './source-read-scope.js';
import { decodeSandboxResourceOptions, normalizeRunSubmitRequest, type RunSubmitRequest } from './control-submit.js';
import { normalizeRunApplyRequest, type RunApplyRequest } from './control-apply.js';
import { decodeSessionContinuityRequest, decodeSessionSummary, type SessionContinuityRequestV1, type SessionContinuityResultV1 } from './session-continuity.js';
import { decodeControlListRequest, decodeControlListResult, validateControlListResponse,
  type ControlListRequestV1, type ControlListResultV1 } from './control-list.js';
import { assertControlWireJson as json, controlWireRecord, controlWireText, controlWireInteger, controlWireRef, decodeControlRange } from './control-wire-data.js';
export { controlWireRecord, controlWireText, controlWireInteger, controlWireRef, decodeControlRange } from './control-wire-data.js';

export const CONTROL_FRAME_BYTES = 1024 * 1024;
export const CONTROL_PROTOCOL_VERSION = 1;
export const HEADLESS_SCHEMA_VERSION = 3;

export type ControlRangeV1 = Readonly<{ min: number; max: number }>;
export type ControlHelloRequestV1 = Readonly<{ protocolVersion: 1; method: 'control.hello'; clientBuild: string;
  controlSchemaRange: ControlRangeV1; headlessSchemaRange: ControlRangeV1; requestedFeatureIds: readonly string[] }>;
export type SessionCreateRequestV1 = Readonly<{ protocolVersion: 1; method: 'session.create'; requestId: string;
  requestDigest: string; admissionKey: string; workspacePath: string; name?: string }>;
export type RunCancelRequestV1 = Readonly<{ protocolVersion: 1; method: 'run.cancel'; requestId: string;
  requestDigest: string; runId: string; expectedRevision: number }>;
export type RunApproveRequestV1 = Readonly<{ protocolVersion: 1; method: 'run.approve'; requestId: string;
  requestDigest: string; runId: string; expectedRevision: number; waitingOnRef: string; decision: 'allow' | 'deny'; ttlMs?: number }>;
export type RunInputRequestV1 = Readonly<{ protocolVersion: 1; method: 'run.input'; requestId: string;
  requestDigest: string; runId: string; expectedRevision: number; waitingOnRef: string; input: UserInputValue }>;
/** Connected publication subset: inspection can be enqueued, never supplied
 * with caller-selected evidence, a target, or manual abandonment authority. */
export type RunReconcileRequestV1 = Readonly<{ protocolVersion: 1; method: 'run.reconcile'; requestId: string;
  requestDigest: string; runId: string; expectedRevision: number; waitingOnRef: string; resolution: Readonly<{ kind: 'probe_now' }> }>;
/** A continuation of an existing operation, deliberately not MutationBase. */
export type CredentialFinalizeRequest = Readonly<{ protocolVersion: 1; method: 'credential.finalize';
  requestId: string; operationId: string; attempt: 1 | 2 | 3; commandDigest: string }>;
export type InstalledControlRequestV1 = ReadControlRequest | ControlHelloRequestV1 | SessionCreateRequestV1 | SessionContinuityRequestV1 | ControlListRequestV1 | RunSubmitRequest |
  RunApplyRequest | RunCancelRequestV1 | RunApproveRequestV1 | RunInputRequestV1 | RunReconcileRequestV1 | AuthorizationCreateRequest | AuthorizationRevokeRequest | CredentialFinalizeRequest |
  Readonly<{ protocolVersion: 1; method: 'supervisor.status' }>;

export type RuntimeBundlePublicSummaryV1 = Readonly<{
  schemaVersion: 1;
  runtimeBundleRef: string;
  bundleDigest: string;
  bundleVersion: string;
}>;

export type SupervisorHelloV1 = Readonly<{
  supervisorInstanceId: string;
  activeRuntimeBundle: RuntimeBundlePublicSummaryV1;
  headlessSchemaRange: Readonly<{ min: number; max: number }>;
}>;

export type SupervisorStatusV1 = Readonly<{
  method: 'supervisor.status';
  health: 'starting' | 'ready' | 'draining' | 'degraded';
  supervisorInstanceId: string;
  queue: Readonly<{ queuedRuns: number; runningRuns: number; capacity: number }>;
  stateSchemaVersion: number;
  activeRuntimeBundle: RuntimeBundlePublicSummaryV1;
  installedRuntimeBundles: readonly RuntimeBundlePublicSummaryV1[];
  incompatiblePinnedRunCount: number;
}>;

export const CONTROL_METHODS_V1 = Object.freeze(['control.hello', 'session.create', 'session.list', 'session.get', 'session.fork',
  'session.compact', 'session.handoff.create', 'run.submit', 'run.list', 'run.get', 'run.attach',
  'run.cancel', 'run.approve', 'run.input', 'run.reconcile', 'run.diff', 'run.result', 'run.apply',
  'authorization.create', 'authorization.list', 'authorization.revoke', 'mcp.register',
  'mcp.refresh', 'mcp.list', 'artifact.get', 'supervisor.status', 'credential.finalize'] as const);
export type ControlMethodV1 = typeof CONTROL_METHODS_V1[number];
export type InstalledControlResultV1 = SessionContinuityResultV1 | ControlListResultV1 | Extract<ControlResultV1, { method: 'session.get' | 'run.get' | 'run.attach' | 'run.result' | 'run.diff' | 'artifact.get' }> | Extract<ControlResultV1, { method: 'session.create' | 'run.submit' | 'run.apply' | 'run.approve' | 'run.input' | 'run.cancel' | 'run.reconcile' }> |
  import('../kernel/authorization.js').AuthorizationResponse['result'] |
  SupervisorStatusV1 | { method: 'credential.finalize'; operation: CredentialAuthorityOperationV1 } | (SupervisorHelloV1 & {
  method: 'control.hello'; protocolVersion: 1; serverBuild: string;
  controlSchemaRange: { min: 1; max: 1 }; enabledFeatureIds: string[];
});
type ErrorBase = { schemaVersion: 1; messageCode: string };
type InvalidError = ErrorBase & { code: 'INVALID_REQUEST'; retryable: false;
  issues: Array<{ path: string; issueCode: string }> };
export type InstalledControlErrorV1 = InvalidError
  | (ErrorBase & { code: 'AUTHORIZATION_REQUIRED'; retryable: false; errorId: string; requiredAuthorization: DependencyInstallScriptsDecisionV1 })
  | import('../kernel/types.js').ResultUnavailableControlErrorV1
  | (ErrorBase & { code: 'RESOURCE_EXHAUSTED'; retryable: true; resourceKind: 'run_queue' | 'state_storage'; retryAfterMs: 1000 })
  | (ErrorBase & { code: 'RATE_LIMITED'; retryable: true; retryAfterMs: 1000 })
  | (ErrorBase & { code: 'INCOMPATIBLE_PROTOCOL'; retryable: false;
      supportedControlRange: { min: 1; max: 1 }; supportedHeadlessRange: ControlRangeV1;
      upgradeAction: 'upgrade_client' | 'upgrade_supervisor' })
  | (ErrorBase & { code: 'EVENT_CURSOR_EXPIRED'; retryable: false;
      earliestEventSeq: number; latestEventSeq: number; snapshot: RunSnapshotV1 })
  | (ErrorBase & { code: 'INTERNAL'; retryable: false; errorId: string })
  | (ErrorBase & { code: 'REVISION_CONFLICT'; retryable: true; currentRevision: number;
      conflict: { resourceKind: 'session'; currentSnapshot: SessionSnapshotV1 } | { resourceKind: 'run'; currentSnapshot: RunSnapshotV1 } })
  | (ErrorBase & { code: 'NOT_FOUND' | 'AUTHORIZATION_REQUIRED' | 'ARTIFACT_MISMATCH' | 'UNSUPPORTED_PLATFORM' |
      'REQUEST_ID_CONFLICT' | 'ADMISSION_KEY_CONFLICT' | 'MODEL_COST_UNKNOWN' | 'BUDGET_EXHAUSTED' | 'CANCEL_REQUESTED' | 'RUN_TERMINAL' |
      'UNSUPPORTED_EXECUTION_IDENTITY'; retryable: false });
export type InstalledControlResponseV1 =
  | { protocolVersion: 1; ok: true; result: InstalledControlResultV1 }
  | { protocolVersion: 1; ok: false; method: ControlMethodV1; error: InstalledControlErrorV1 }
  | { protocolVersion: 1; ok: false; rejectedMethodDigest: string; error: InvalidError };


/** Connected composition ceiling; a hello still intersects this with the actual installed Store. */
export const INSTALLED_CONTROL_FEATURES = Object.freeze(['session.get', 'run.get', 'run.attach', 'supervisor.status', 'credential.finalize',
  'session.create', 'session.list', 'session.fork', 'session.compact', 'session.handoff.create', 'run.submit', 'run.list', 'run.cancel', 'authorization.create', 'authorization.list', 'authorization.revoke', 'run.result', 'run.diff', 'artifact.get', 'run.apply', 'run.approve', 'run.input', 'run.reconcile'] as const);
export type InstalledControlFeature = typeof INSTALLED_CONTROL_FEATURES[number];
export type InstalledControlMethod = InstalledControlRequestV1['method'];
export type InstalledControlResultFor<M extends InstalledControlMethod> = Extract<InstalledControlResultV1, { method: M }>;
export type InstalledControlResponseFor<M extends InstalledControlMethod> =
  | { protocolVersion: 1; ok: true; result: InstalledControlResultFor<M> }
  | { protocolVersion: 1; ok: false; method: M; error: InstalledControlErrorV1 };

/** Framing data only: no request method, principal or authority is inferred. */
export function decodeControlFrame(bytes: Uint8Array): unknown {
  if (bytes.byteLength < 1 || bytes.byteLength > CONTROL_FRAME_BYTES) throw new TypeError('control frame exceeds its bound');
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('noncanonical control frame');
  return value;
}

export type ReadControlRequest =
  | { protocolVersion: 1; method: 'session.get'; sessionId: string; afterItemSeq?: number; limit?: number }
  | { protocolVersion: 1; method: 'run.get'; runId: string; afterItemSeq?: number; afterJournalSeq?: number;
      checkpointCursor?: string; itemLimit?: number; journalLimit?: number; checkpointLimit?: number }
  | { protocolVersion: 1; method: 'run.result'; runId: string }
  | { protocolVersion: 1; method: 'run.diff'; runId: string }
  | { protocolVersion: 1; method: 'artifact.get'; digest: string; offset: number; length: number }
  | { protocolVersion: 1; method: 'run.attach'; runId: string; afterEventSeq: number; limit?: number };

const limit = (value: unknown) => controlWireInteger(value === undefined ? 100 : value, 1, 1000);
export function decodeReadControlRequest(value: unknown): ReadControlRequest {
  const source = controlWireRecord(value, ['protocolVersion', 'method'], ['sessionId', 'runId', 'digest', 'offset', 'length',
    'afterItemSeq', 'afterJournalSeq', 'checkpointCursor', 'itemLimit', 'journalLimit', 'checkpointLimit', 'afterEventSeq', 'limit']);
  if (source.protocolVersion !== 1) throw new TypeError('control protocol version must be 1');
  const method = source.method;
  if (method === 'artifact.get') {
    controlWireRecord(source, ['protocolVersion', 'method', 'digest', 'offset', 'length']);
    return { protocolVersion: 1, method, digest: controlWireRef(source.digest), offset: controlWireInteger(source.offset),
      length: controlWireInteger(source.length, 1, 4 * 1024 * 1024) };
  }
  if (method === 'run.result' || method === 'run.diff') {
    controlWireRecord(source, ['protocolVersion', 'method', 'runId']);
    return { protocolVersion: 1, method, runId: controlWireText(source.runId) };
  }
  if (method === 'session.get') {
    controlWireRecord(source, ['protocolVersion', 'method', 'sessionId'], ['afterItemSeq', 'limit']);
    return { protocolVersion: 1, method, sessionId: controlWireText(source.sessionId),
      afterItemSeq: controlWireInteger(source.afterItemSeq === undefined ? 0 : source.afterItemSeq), limit: limit(source.limit) };
  }
  if (method === 'run.get') {
    controlWireRecord(source, ['protocolVersion', 'method', 'runId'], ['afterItemSeq', 'afterJournalSeq', 'checkpointCursor', 'itemLimit', 'journalLimit', 'checkpointLimit']);
    if (Object.hasOwn(source, 'checkpointCursor') && (typeof source.checkpointCursor !== 'string' || source.checkpointCursor.length > 1024))
      throw new TypeError('Checkpoint cursor must be a bounded string');
    return { protocolVersion: 1, method, runId: controlWireText(source.runId),
      afterItemSeq: controlWireInteger(source.afterItemSeq === undefined ? 0 : source.afterItemSeq),
      afterJournalSeq: controlWireInteger(source.afterJournalSeq === undefined ? 0 : source.afterJournalSeq),
      itemLimit: limit(source.itemLimit), journalLimit: limit(source.journalLimit), checkpointLimit: limit(source.checkpointLimit),
      ...(Object.hasOwn(source, 'checkpointCursor') ? { checkpointCursor: source.checkpointCursor as string } : {}) };
  }
  if (method === 'run.attach') {
    controlWireRecord(source, ['protocolVersion', 'method', 'runId', 'afterEventSeq'], ['limit']);
    return { protocolVersion: 1, method, runId: controlWireText(source.runId), afterEventSeq: controlWireInteger(source.afterEventSeq), limit: limit(source.limit) };
  }
  throw new TypeError('unsupported installed read method');
}
export function decodeControlHelloRequest(value: unknown): ControlHelloRequestV1 {
  json(value);
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'clientBuild', 'controlSchemaRange', 'headlessSchemaRange', 'requestedFeatureIds']);
  if (data.protocolVersion !== 1 || data.method !== 'control.hello' || !Array.isArray(data.requestedFeatureIds) || data.requestedFeatureIds.length > 64)
    throw new TypeError('invalid control hello');
  const requestedFeatureIds = data.requestedFeatureIds.map(value => controlWireText(value));
  if (new Set(requestedFeatureIds).size !== requestedFeatureIds.length) throw new TypeError('duplicate requested feature');
  return { protocolVersion: 1, method: 'control.hello', clientBuild: controlWireText(data.clientBuild),
    controlSchemaRange: decodeControlRange(data.controlSchemaRange), headlessSchemaRange: decodeControlRange(data.headlessSchemaRange), requestedFeatureIds };
}
export function decodeSessionCreatePublicRequest(value: unknown): { core: Omit<SessionCreateRequestV1, 'requestDigest'>; requestDigest: string } {
  json(value);
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'admissionKey', 'workspacePath'], ['name']);
  if (data.protocolVersion !== 1 || data.method !== 'session.create' || typeof data.requestId !== 'string' ||
      typeof data.admissionKey !== 'string' || typeof data.workspacePath !== 'string') throw new TypeError('invalid session.create');
  assertRequestId(data.requestId); assertAdmissionKey(data.admissionKey); normalizeAbsolutePath(data.workspacePath);
  if (Object.hasOwn(data, 'name')) {
    if (typeof data.name !== 'string') throw new TypeError('Session name must be text');
    normalizeBoundedText(data.name, 1, 256);
  }
  const { requestDigest, ...core } = data;
  if (typeof requestDigest !== 'string' || canonicalSha256(core) !== requestDigest) throw new TypeError('session.create public request digest differs');
  return immutableSnapshot({ core: core as Omit<SessionCreateRequestV1, 'requestDigest'>, requestDigest });
}
export class UnsupportedExecutionIdentityRequestError extends TypeError {}
export function decodeAuthorizationCreateRequest(value: unknown): AuthorizationCreateRequest {
  json(value);
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'decision'], ['ttlMs']);
  const decision = controlWireRecord(data.decision, ['kind', 'purpose', 'target']);
  if (decision.kind === 'dependency_install_scripts') {
    if (data.protocolVersion !== 1 || data.method !== 'authorization.create') throw new TypeError('invalid dependency authorization method');
    decodeDependencyInstallScriptsDecision(decision);
    assertRequestId(data.requestId as string); controlWireRef(data.requestDigest);
    const { requestDigest, ...core } = data;
    if (canonicalSha256(core) !== requestDigest) throw new TypeError('authorization request digest does not rehash');
    if (Object.hasOwn(data, 'ttlMs')) controlWireInteger(data.ttlMs, 1, 86_400_000);
    return immutableSnapshot(data) as DependencyInstallScriptsCreateRequest;
  }
  if (decision.kind === 'read_scope') {
    if (data.protocolVersion !== 1 || data.method !== 'authorization.create' || decision.purpose !== 'source')
      throw new TypeError('invalid source read authorization');
    assertRequestId(data.requestId as string); controlWireRef(data.requestDigest);
    const { requestDigest, ...core } = data;
    if (canonicalSha256(core) !== requestDigest) throw new TypeError('authorization request digest does not rehash');
    const target = controlWireRecord(decision.target, ['sessionId', 'expectedWorkspaceIdentityDigest', 'path', 'scope'], ['expectedDigest']);
    controlWireText(target.sessionId); controlWireRef(target.expectedWorkspaceIdentityDigest);
    normalizeSourceReadScopePath(target.path, target.scope);
    if (Object.hasOwn(target, 'expectedDigest')) controlWireRef(target.expectedDigest);
    if (Object.hasOwn(data, 'ttlMs')) controlWireInteger(data.ttlMs, 1, 86_400_000);
    return immutableSnapshot(data) as SourceReadScopeCreateRequest;
  }
  if (decision.kind !== 'source_git_inspection') return decodeVerifierIdentityCreateRequest(value);
  if (data.protocolVersion !== 1 || data.method !== 'authorization.create' || decision.purpose !== 'source_inspection')
    throw new TypeError('invalid source inspection authorization');
  assertRequestId(data.requestId as string); controlWireRef(data.requestDigest);
  const { requestDigest, ...core } = data;
  if (canonicalSha256(core) !== requestDigest) throw new TypeError('authorization request digest does not rehash');
  const target = controlWireRecord(decision.target, ['sessionId', 'expectedWorkspaceIdentityDigest', 'scope', 'recipe', 'retention', 'resourceCeiling']);
  controlWireText(target.sessionId); controlWireRef(target.expectedWorkspaceIdentityDigest);
  if (target.scope !== 'in_root_git_metadata_and_objects' || target.recipe !== 'cliq-source-git-inspection-v1' ||
      target.retention !== 'ephemeral_raw_reachable_only') throw new TypeError('source inspection authorization has another scope or retention');
  // Consent fixes every resource; defaults are not inferred at this boundary.
  const resources = decodeSandboxResourceOptions(target.resourceCeiling);
  controlWireRecord(target.resourceCeiling, Object.keys(resources));
  if (Object.hasOwn(data, 'ttlMs')) controlWireInteger(data.ttlMs, 1, 86_400_000);
  return immutableSnapshot(data) as SourceGitInspectionCreateRequest;
}
/** Exact intent data. Only a later owning capture/Run transaction can consume
 * an authorization; decoding this value supplies no native or source fact. */
export function decodeDependencyInstallScriptsDecision(value: unknown): DependencyInstallScriptsDecisionV1 {
  const decision = controlWireRecord(value, ['kind', 'purpose', 'target']);
  if (decision.kind !== 'dependency_install_scripts' || decision.purpose !== 'dependency_install_scripts') throw new TypeError('invalid dependency script consent');
  const target = controlWireRecord(decision.target, ['sessionId', 'sourceInspectionId', 'expectedWorkspaceIdentityDigest', 'conditions']);
  controlWireText(target.sessionId); controlWireRef(target.expectedWorkspaceIdentityDigest);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(controlWireText(target.sourceInspectionId))) throw new TypeError('invalid dependency capture locator');
  decodeDependencyScriptConditions(target.conditions);
  return immutableSnapshot(decision) as DependencyInstallScriptsDecisionV1;
}
export function decodeVerifierIdentityCreateRequest(value: unknown): VerifierIdentityCreateRequest {
  json(value);
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'decision'], ['ttlMs']);
  if (data.protocolVersion !== 1 || data.method !== 'authorization.create') throw new TypeError('invalid authorization method');
  assertRequestId(data.requestId as string); controlWireRef(data.requestDigest);
  const { requestDigest, ...core } = data;
  if (canonicalSha256(core) !== requestDigest) throw new TypeError('authorization request digest does not rehash');
  const decision = data.decision as Record<string, unknown> | null;
  if (decision === null || typeof decision !== 'object' || Array.isArray(decision)) throw new TypeError('authorization decision is not a record');
  const target = decision?.target as Record<string, unknown> | null;
  if (decision?.kind !== 'execution_identity_read' || decision?.purpose !== 'verifier' || target?.kind !== 'guest_toolchain')
    throw new UnsupportedExecutionIdentityRequestError('unsupported execution identity');
  controlWireRecord(decision, ['kind', 'purpose', 'target']);
  controlWireRecord(target, ['kind', 'guestToolchainManifestId', 'toolId']);
  controlWireText(target.guestToolchainManifestId); controlWireText(target.toolId);
  if (Object.hasOwn(data, 'ttlMs')) controlWireInteger(data.ttlMs, 1, 86_400_000);
  return immutableSnapshot(data) as VerifierIdentityCreateRequest;
}
export function decodeAuthorizationRevokeRequest(value: unknown): AuthorizationRevokeRequest {
  json(value);
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'grantId']);
  if (data.protocolVersion !== 1 || data.method !== 'authorization.revoke') throw new TypeError('invalid authorization method');
  assertRequestId(data.requestId as string); controlWireRef(data.requestDigest); controlWireText(data.grantId);
  const { requestDigest, ...core } = data;
  if (canonicalSha256(core) !== requestDigest) throw new TypeError('authorization revoke digest does not rehash');
  return immutableSnapshot(data) as AuthorizationRevokeRequest;
}
export function decodeCredentialFinalizeRequest(value: unknown): CredentialFinalizeRequest {
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'operationId', 'attempt', 'commandDigest']);
  if (data.protocolVersion !== 1 || data.method !== 'credential.finalize' || typeof data.requestId !== 'string' ||
      typeof data.operationId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(data.operationId) || ![1, 2, 3].includes(data.attempt as number))
    throw new TypeError('invalid original credential continuation');
  assertRequestId(data.requestId); controlWireRef(data.commandDigest);
  return immutableSnapshot(data) as CredentialFinalizeRequest;
}
export function decodeInstalledControlRequest(value: unknown): InstalledControlRequestV1 {
  json(value);
  assertBoundedJsonValue(value, 'control request');
  if (canonicalJsonBytes(value).byteLength > CONTROL_FRAME_BYTES) throw new TypeError('control request exceeds its bound');
  const source = value as Record<string, unknown>;
  if (source?.method === 'control.hello') return immutableSnapshot(decodeControlHelloRequest(source));
  if (source?.method === 'supervisor.status') {
    controlWireRecord(source, ['protocolVersion', 'method']);
    if (source.protocolVersion !== 1) throw new TypeError('control protocol version must be 1');
    return immutableSnapshot(source) as Extract<InstalledControlRequestV1, { method: 'supervisor.status' }>;
  }
  if (source?.method === 'session.create') {
    const { core, requestDigest } = decodeSessionCreatePublicRequest(source); return immutableSnapshot({ ...core, requestDigest });
  }
  if (['session.list', 'session.fork', 'session.compact', 'session.handoff.create'].includes(source?.method as string)) return decodeSessionContinuityRequest(source);
  if (source?.method === 'run.list' || source?.method === 'authorization.list') return decodeControlListRequest(source);
  if (source?.method === 'run.submit') return normalizeRunSubmitRequest(source).originalRequest as RunSubmitRequest;
  if (source?.method === 'run.apply') return normalizeRunApplyRequest(source).originalRequest as RunApplyRequest;
  if (source?.method === 'run.reconcile') {
    controlWireRecord(source, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'runId', 'expectedRevision', 'waitingOnRef', 'resolution']);
    if (source.protocolVersion !== 1) throw new TypeError('control protocol version must be 1');
    assertRequestId(source.requestId as string); controlWireRef(source.requestDigest); controlWireText(source.runId);
    controlWireInteger(source.expectedRevision, 1); controlWireRef(source.waitingOnRef);
    const resolution = controlWireRecord(source.resolution, ['kind']);
    if (resolution.kind !== 'probe_now') throw new TypeError('unsupported installed reconciliation resolution');
    const { requestDigest, ...core } = source;
    if (canonicalSha256(core) !== requestDigest) throw new TypeError('run.reconcile request digest differs');
    return immutableSnapshot(source) as RunReconcileRequestV1;
  }
  if (source?.method === 'run.approve') {
    controlWireRecord(source, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'runId', 'expectedRevision', 'waitingOnRef', 'decision'], ['ttlMs']);
    if (source.protocolVersion !== 1 || !['allow', 'deny'].includes(source.decision as string)) throw new TypeError('invalid run.approve decision');
    assertRequestId(source.requestId as string); controlWireRef(source.requestDigest); controlWireText(source.runId);
    controlWireInteger(source.expectedRevision, 1); controlWireRef(source.waitingOnRef);
    if (Object.hasOwn(source, 'ttlMs')) controlWireInteger(source.ttlMs, 1, 86_400_000);
    const { requestDigest, ...core } = source;
    if (canonicalSha256(core) !== requestDigest) throw new TypeError('run.approve request digest differs');
    return immutableSnapshot(source) as RunApproveRequestV1;
  }
  if (source?.method === 'run.input') {
    controlWireRecord(source, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'runId', 'expectedRevision', 'waitingOnRef', 'input']);
    if (source.protocolVersion !== 1) throw new TypeError('control protocol version must be 1');
    assertRequestId(source.requestId as string); controlWireRef(source.requestDigest); controlWireText(source.runId);
    controlWireInteger(source.expectedRevision, 1); controlWireRef(source.waitingOnRef);
    const input = controlWireRecord(source.input, ['kind', 'value']);
    if (input.kind !== 'json' && input.kind !== 'text' || input.kind === 'text' && typeof input.value !== 'string')
      throw new TypeError('invalid run.input value');
    assertBoundedJsonValue(input.value, 'user input');
    if (canonicalJsonBytes(input.value).byteLength > 1_048_576) throw new TypeError('user input exceeds its bound');
    const { requestDigest, ...core } = source;
    if (canonicalSha256(core) !== requestDigest) throw new TypeError('run.input request digest differs');
    return immutableSnapshot(source) as RunInputRequestV1;
  }
  if (source?.method === 'run.cancel') {
    controlWireRecord(source, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'runId', 'expectedRevision']);
    if (source.protocolVersion !== 1) throw new TypeError('control protocol version must be 1');
    assertRequestId(source.requestId as string); controlWireRef(source.requestDigest); controlWireText(source.runId); controlWireInteger(source.expectedRevision, 1);
    const { requestDigest, ...core } = source;
    if (canonicalSha256(core) !== requestDigest) throw new TypeError('run.cancel request digest differs');
    return immutableSnapshot(source) as RunCancelRequestV1;
  }
  if (source?.method === 'authorization.create') return decodeAuthorizationCreateRequest(source);
  if (source?.method === 'authorization.revoke') return decodeAuthorizationRevokeRequest(source);
  if (source?.method === 'credential.finalize') return decodeCredentialFinalizeRequest(source);
  return immutableSnapshot(decodeReadControlRequest(source));
}
function rangeOverlap(left: ControlRangeV1, right: ControlRangeV1): boolean { return left.min <= right.max && right.min <= left.max; }
function array(value: unknown): unknown[] { if (!Array.isArray(value)) throw new TypeError('control collection must be an array'); return value; }
function runSnapshot(value: unknown): RunSnapshotV1 {
  const data = controlWireRecord(value, ['schemaVersion', 'operation', 'run', 'latestRunItemSeq']);
  if (data.schemaVersion !== 1 || !['agent', 'delivery'].includes(data.operation as string)) throw new TypeError('invalid Run snapshot');
  decodeWireRun(data.run); controlWireInteger(data.latestRunItemSeq); return data as RunSnapshotV1;
}
function sessionSnapshot(value: unknown): SessionSnapshotV1 {
  const data = controlWireRecord(value, ['schemaVersion', 'session']);
  if (data.schemaVersion !== 1) throw new TypeError('invalid Session snapshot');
  decodeWireSession(data.session); return data as SessionSnapshotV1;
}
function result(value: unknown, method: InstalledControlMethod): InstalledControlResultV1 {
  const data = value as Record<string, unknown>;
  if (data?.method !== method) throw new TypeError('unexpected installed control response method');
  if (method === 'run.list' || method === 'authorization.list') return decodeControlListResult(value, method);
  if (method === 'control.hello') {
    controlWireRecord(data, ['method', 'protocolVersion', 'serverBuild', 'controlSchemaRange', 'enabledFeatureIds', 'supervisorInstanceId', 'activeRuntimeBundle', 'headlessSchemaRange']);
    const control = decodeControlRange(data.controlSchemaRange); decodeControlRange(data.headlessSchemaRange);
    if (data.protocolVersion !== 1 || control.min !== 1 || control.max !== 1) throw new TypeError('invalid control hello version');
    controlWireText(data.serverBuild); controlWireText(data.supervisorInstanceId); decodeWireRuntimeBundleSummary(data.activeRuntimeBundle);
    const features = array(data.enabledFeatureIds).map(value => controlWireText(value));
    if (features.length > 64 || new Set(features).size !== features.length || features.some(value => !INSTALLED_CONTROL_FEATURES.includes(value as InstalledControlFeature)))
      throw new TypeError('invalid enabled installed features');
  } else if (method === 'supervisor.status') {
    controlWireRecord(data, ['method', 'health', 'supervisorInstanceId', 'queue', 'stateSchemaVersion', 'activeRuntimeBundle', 'installedRuntimeBundles', 'incompatiblePinnedRunCount']);
    if (!['starting', 'ready', 'draining', 'degraded'].includes(data.health as string)) throw new TypeError('invalid Supervisor health');
    controlWireText(data.supervisorInstanceId); controlWireInteger(data.stateSchemaVersion, 1); controlWireInteger(data.incompatiblePinnedRunCount);
    const queue = controlWireRecord(data.queue, ['queuedRuns', 'runningRuns', 'capacity']);
    for (const field of ['queuedRuns', 'runningRuns', 'capacity']) controlWireInteger(queue[field]);
    decodeWireRuntimeBundleSummary(data.activeRuntimeBundle); array(data.installedRuntimeBundles).forEach(decodeWireRuntimeBundleSummary);
  } else if (method === 'credential.finalize') {
    controlWireRecord(data, ['method', 'operation']);
    if (decodeCredentialAuthorityOperation(data.operation).phase !== 'committed') throw new TypeError('credential finalization is not committed');
  } else if (method === 'session.create' || method === 'session.fork' || method === 'session.compact') {
    controlWireRecord(data, ['method', 'snapshot']); sessionSnapshot(data.snapshot);
  } else if (method === 'session.list') {
    controlWireRecord(data, ['method', 'sessions'], ['nextCursor']);
    const sessions = array(data.sessions).map(decodeSessionSummary);
    if (sessions.length > 100 || new Set(sessions.map(session => session.id)).size !== sessions.length) throw new TypeError('Session list contains too many or repeated entries');
    for (let index = 1; index < sessions.length; index++) {
      const before = sessions[index - 1]!, after = sessions[index]!;
      if (before.createdAt > after.createdAt || before.createdAt === after.createdAt && Buffer.compare(Buffer.from(before.id), Buffer.from(after.id)) >= 0) throw new TypeError('Session list order differs');
    }
    if (Object.hasOwn(data, 'nextCursor')) controlWireText(data.nextCursor, 512);
  } else if (method === 'session.handoff.create') {
    controlWireRecord(data, ['method', 'json', 'markdown']);
    decodeWireArtifactDescriptor(data.json); decodeWireArtifactDescriptor(data.markdown);
  } else if (method === 'authorization.create' || method === 'authorization.revoke') {
    controlWireRecord(data, ['method', 'grant', ...(method === 'authorization.revoke' ? ['disposition'] : [])]); decodeWireGrantSummary(data.grant);
    if (method === 'authorization.revoke' && !['revoked', 'already_revoked', 'already_consumed'].includes(data.disposition as string))
      throw new TypeError('invalid authorization revocation disposition');
  } else if (method === 'run.submit' || method === 'run.apply' || method === 'run.cancel') {
    controlWireRecord(data, ['method', 'snapshot']); runSnapshot(data.snapshot);
  } else if (method === 'run.approve') {
    controlWireRecord(data, ['method', 'snapshot', 'decisionRef']); runSnapshot(data.snapshot); controlWireRef(data.decisionRef);
  } else if (method === 'run.input') {
    controlWireRecord(data, ['method', 'snapshot', 'inputItemRef']);
    const snapshot = runSnapshot(data.snapshot); controlWireRef(data.inputItemRef);
    if (snapshot.operation !== 'agent' || snapshot.run.status !== 'queued' || snapshot.run.activeWorkerLaunchId !== undefined ||
        snapshot.run.waitingReason !== undefined || snapshot.run.waitingOnRef !== undefined)
      throw new TypeError('input response is not its exact worker-free continuation');
  } else if (method === 'run.reconcile') {
    controlWireRecord(data, ['method', 'snapshot', 'resolution']);
    const snapshot = runSnapshot(data.snapshot), resolution = controlWireRecord(data.resolution, ['kind', 'dispatchDigest', 'userProbeCount']);
    if (resolution.kind !== 'probe_enqueued' || snapshot.run.status !== 'waiting' || snapshot.run.waitingReason !== 'reconciliation')
      throw new TypeError('reconciliation response is not its persisted inspection enqueue');
    controlWireRef(resolution.dispatchDigest); controlWireInteger(resolution.userProbeCount, 1);
  } else if (method === 'run.result' || method === 'run.diff') {
    controlWireRecord(data, ['method', 'runId', ...(method === 'run.result' ? ['result', 'verificationClosureRef'] : ['diff'])]);
    controlWireText(data.runId); decodeWireArtifactDescriptor(data[method === 'run.result' ? 'result' : 'diff']);
    if (method === 'run.result') controlWireRef(data.verificationClosureRef);
  } else if (method === 'artifact.get') {
    controlWireRecord(data, ['method', 'artifact', 'offset', 'bytesBase64', 'nextOffset', 'eof']);
    const artifact = decodeWireArtifactDescriptor(data.artifact), offset = controlWireInteger(data.offset), next = controlWireInteger(data.nextOffset);
    if (typeof data.bytesBase64 !== 'string' || typeof data.eof !== 'boolean') throw new TypeError('invalid artifact page');
    const bytes = Buffer.from(data.bytesBase64, 'base64');
    if (bytes.toString('base64') !== data.bytesBase64 || bytes.length > 64 * 1024 || next !== offset + bytes.length || next > artifact.sizeBytes ||
        data.eof !== (next === artifact.sizeBytes) || (!data.eof && bytes.length === 0)) throw new TypeError('invalid bounded artifact page');
  } else if (method === 'session.get') {
    controlWireRecord(data, ['method', 'snapshot', 'items', 'highWaterItemSeq', 'nextItemSeq']);
    const snapshot = sessionSnapshot(data.snapshot); array(data.items).forEach(decodeWireSessionItem);
    if (controlWireInteger(data.highWaterItemSeq) !== snapshot.session.latestItemSeq || controlWireInteger(data.nextItemSeq) > snapshot.session.latestItemSeq)
      throw new TypeError('Session page exceeds its high-water');
  } else if (method === 'run.get') {
    controlWireRecord(data, ['method', 'snapshot', 'items', 'journal', 'checkpoints', 'highWaterItemSeq', 'highWaterJournalSeq', 'highWaterCheckpointCursor', 'nextItemSeq', 'nextJournalSeq'], ['nextCheckpointCursor']);
    const snapshot = runSnapshot(data.snapshot); array(data.items).forEach(decodeWireRunItemReference);
    array(data.journal).forEach(decodeWireJournal); array(data.checkpoints).forEach(decodeWireCheckpoint);
    if (controlWireInteger(data.highWaterItemSeq) !== snapshot.latestRunItemSeq || controlWireInteger(data.nextItemSeq) > snapshot.latestRunItemSeq ||
        controlWireInteger(data.nextJournalSeq) > controlWireInteger(data.highWaterJournalSeq)) throw new TypeError('Run page exceeds its high-water');
    checkpointPosition(data.highWaterCheckpointCursor, snapshot.run.id);
    if (Object.hasOwn(data, 'nextCheckpointCursor')) checkpointPosition(data.nextCheckpointCursor, snapshot.run.id);
  } else if (method === 'run.attach') {
    controlWireRecord(data, ['method', 'snapshot', 'earliestRetainedEventSeq', 'latestRetainedEventSeq', 'highWaterEventSeq', 'events', 'nextEventSeq']);
    const snapshot = runSnapshot(data.snapshot), earliest = controlWireInteger(data.earliestRetainedEventSeq, 1), latest = controlWireInteger(data.latestRetainedEventSeq, earliest);
    if (controlWireInteger(data.highWaterEventSeq, 1) !== latest || controlWireInteger(data.nextEventSeq) > latest) throw new TypeError('event page exceeds its retained interval');
    array(data.events).forEach(event => decodeWireEvent(event, snapshot));
  } else throw new TypeError('unimplemented installed control result');
  return data as InstalledControlResultV1;
}
export type ControlCheckpointPosition = Readonly<{ createdAt: string; checkpointId: string }>;
export function encodeControlCheckpointCursor(runId: string, position: ControlCheckpointPosition): string {
  return canonicalJsonBytes({ schemaVersion: 1, runId, createdAt: position.createdAt, checkpointId: position.checkpointId }).toString('base64url');
}
export function decodeControlCheckpointCursor(value: unknown, runId: string): ControlCheckpointPosition {
  if (typeof value !== 'string' || value.length > 1024 || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new TypeError('invalid Checkpoint cursor');
  const bytes = Buffer.from(value, 'base64url');
  const data = controlWireRecord(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), ['schemaVersion', 'runId', 'createdAt', 'checkpointId']);
  if (data.schemaVersion !== 1 || data.runId !== runId || bytes.toString('base64url') !== value || !canonicalJsonBytes(data).equals(bytes) || typeof data.createdAt !== 'string')
    throw new TypeError('Checkpoint cursor differs from its Run or canonical bytes');
  parseCanonicalTime(data.createdAt); controlWireText(data.checkpointId); return data as ControlCheckpointPosition;
}
const checkpointPosition = decodeControlCheckpointCursor;
function compareCheckpoint(left: ControlCheckpointPosition, right: ControlCheckpointPosition): number {
  return Buffer.compare(Buffer.from(left.createdAt), Buffer.from(right.createdAt)) || Buffer.compare(Buffer.from(left.checkpointId), Buffer.from(right.checkpointId));
}
function canonicalResponseText(value: unknown): void {
  if (typeof value === 'string') {
    if (normalizeCanonicalText(value) !== value) throw new TypeError('control response text is not canonical');
  } else if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (normalizeCanonicalText(key) !== key) throw new TypeError('control response key is not canonical');
      canonicalResponseText(child);
    }
  }
}
function contiguous<T>(items: readonly T[], after: number, high: number, maximum: number,
  next: number, sequence: (item: T) => number): void {
  if (after > high || items.length > maximum || items.some((item, index) => sequence(item) !== after + index + 1) ||
      next !== after + items.length || next > high) throw new TypeError('control page has a sequence gap or invalid cursor');
}
/** Strict closed envelope. This is data only; it neither authenticates a peer
 * nor proves registration, artifact membership, authorization or retirement. */
export function decodeInstalledControlEnvelope<M extends InstalledControlMethod>(value: unknown, method: M): InstalledControlResponseFor<M> {
  json(value);
  assertBoundedJsonValue(value, 'control response');
  // Response wire text is canonical without silently normalizing retained
  // Journal strings. Public mutation inputs deliberately retain their supplied
  // Unicode bytes in the original request-digest domain instead.
  canonicalResponseText(value);
  if (canonicalJsonBytes(value).byteLength > CONTROL_FRAME_BYTES) throw new TypeError('control response exceeds its bound');
  const envelope = value as Record<string, unknown>;
  if (envelope?.ok === false) {
    controlWireRecord(envelope, ['protocolVersion', 'ok', 'method', 'error']);
    if (envelope.protocolVersion !== 1 || envelope.method !== method) throw new TypeError('unexpected control refusal');
    decodeInstalledControlError(envelope.error, method);
  } else {
    controlWireRecord(envelope, ['protocolVersion', 'ok', 'result']);
    if (envelope.protocolVersion !== 1 || envelope.ok !== true) throw new TypeError('invalid control response');
    result(envelope.result, method);
  }
  return immutableSnapshot(envelope) as InstalledControlResponseFor<M>;
}
export function decodeInstalledControlResponse<M extends InstalledControlMethod>(value: unknown,
  supplied: Extract<InstalledControlRequestV1, { method: M }>): InstalledControlResponseFor<M> {
  const request = decodeInstalledControlRequest(supplied);
  const response = decodeInstalledControlEnvelope(value, request.method);
  if (!response.ok) {
    const error = response.error;
    if (error.code === 'AUTHORIZATION_REQUIRED' && 'requiredAuthorization' in error &&
        (request.method !== 'run.submit' || request.dependency.mode !== 'locked' || !request.dependency.allowInstallScripts ||
          error.requiredAuthorization.target.sessionId !== request.sessionId)) throw new TypeError('dependency consent refusal differs from its requested Session and effect');
    if (error.code === 'RESULT_UNAVAILABLE' && (!('runId' in request) || error.runId !== request.runId)) throw new TypeError('result refusal differs from requested Run');
    if (error.code === 'EVENT_CURSOR_EXPIRED' && (request.method !== 'run.attach' || error.snapshot.run.id !== request.runId || request.afterEventSeq >= error.earliestEventSeq - 1))
      throw new TypeError('expired cursor refusal differs from requested interval');
    if (error.code === 'REVISION_CONFLICT') {
      const conflict = error.conflict;
      if ((request.method === 'run.submit' || request.method === 'session.fork' || request.method === 'session.compact' || request.method === 'session.handoff.create') && conflict.resourceKind === 'session') {
        if (conflict.currentSnapshot.session.id !== request.sessionId) throw new TypeError('revision conflict differs from requested Session');
      } else if ((request.method === 'run.cancel' || request.method === 'run.approve' || request.method === 'run.input' || request.method === 'run.reconcile') && conflict.resourceKind === 'run') {
        if (conflict.currentSnapshot.run.id !== request.runId) throw new TypeError('revision conflict differs from requested Run');
      } else throw new TypeError('revision conflict has the wrong resource kind');
    }
    return response as InstalledControlResponseFor<M>;
  }
  const data = response.result;
  if ((request.method === 'run.list' || request.method === 'authorization.list') &&
      (data.method === 'run.list' || data.method === 'authorization.list')) validateControlListResponse(data, request);
  if (request.method === 'control.hello' && data.method === request.method) {
    if (!rangeOverlap(request.controlSchemaRange, data.controlSchemaRange) || !rangeOverlap(request.headlessSchemaRange, data.headlessSchemaRange) ||
        data.enabledFeatureIds.some(feature => !request.requestedFeatureIds.includes(feature)) ||
        !canonicalJsonBytes(data.enabledFeatureIds).equals(canonicalJsonBytes(request.requestedFeatureIds.filter(feature => data.enabledFeatureIds.includes(feature)))))
      throw new TypeError('hello features or schema ranges differ from request');
  } else if (request.method === 'artifact.get' && data.method === request.method) {
    if (data.artifact.digest !== request.digest || data.offset !== request.offset || Buffer.from(data.bytesBase64, 'base64').length > request.length)
      throw new TypeError('artifact page does not bind its request');
  } else if ((request.method === 'run.result' || request.method === 'run.diff') && (data.method === 'run.result' || data.method === 'run.diff')) {
    if (data.runId !== request.runId) throw new TypeError('result differs from requested Run');
  } else if (request.method === 'credential.finalize' && data.method === request.method) {
    if (data.operation.operationId !== request.operationId || data.operation.requestId !== request.requestId || data.operation.attempt !== request.attempt || data.operation.requestDigest !== request.commandDigest)
      throw new TypeError('credential finalization differs from original operation');
  } else if (request.method === 'session.fork' && data.method === request.method) {
    if (data.snapshot.session.parentSessionId !== request.sessionId || data.snapshot.session.forkedThroughItemSeq !== request.throughItemSeq ||
        data.snapshot.session.contextRevision !== 1 || data.snapshot.session.latestItemSeq !== request.throughItemSeq || data.snapshot.session.id === request.sessionId)
      throw new TypeError('forked Session differs from its original source prefix');
  } else if (request.method === 'session.compact' && data.method === request.method) {
    if (data.snapshot.session.id !== request.sessionId || data.snapshot.session.contextRevision !== request.expectedContextRevision + 1 || data.snapshot.session.latestItemSeq <= request.throughItemSeq)
      throw new TypeError('compacted Session differs from its original revision');
  } else if (request.method === 'session.list' && data.method === request.method) {
    if (data.sessions.length > (request.limit ?? 50) || data.nextCursor !== undefined && data.sessions.length !== (request.limit ?? 50)) throw new TypeError('Session list exceeds requested page');
  } else if (request.method === 'run.submit' && data.method === request.method) {
    if (data.snapshot.operation !== 'agent' || data.snapshot.run.sessionId !== request.sessionId) throw new TypeError('submitted Run differs from Session');
  } else if (request.method === 'run.apply' && data.method === request.method) {
    if (data.snapshot.operation !== 'delivery' || data.snapshot.run.id === request.sourceRunId)
      throw new TypeError('applied Run is not a distinct explicit delivery');
  } else if ((request.method === 'run.cancel' && data.method === request.method) || (request.method === 'run.approve' && data.method === request.method)) {
    if (data.snapshot.run.id !== request.runId) throw new TypeError('cancelled Run differs from request');
  } else if (request.method === 'run.input' && data.method === request.method) {
    if (data.snapshot.run.id !== request.runId || data.snapshot.run.revision !== request.expectedRevision + 1)
      throw new TypeError('input response differs from its original Run and revision');
  } else if (request.method === 'run.reconcile' && data.method === request.method) {
    if (data.snapshot.run.id !== request.runId || data.snapshot.run.revision !== request.expectedRevision + 1 ||
        data.snapshot.run.waitingOnRef === request.waitingOnRef)
      throw new TypeError('inspection enqueue differs from its exact original Run and wait');
  } else if (request.method === 'authorization.create' && data.method === request.method) {
    if (data.grant.state !== 'active' || data.grant.targetKind !== request.decision.kind || data.grant.purpose !== request.decision.purpose)
      throw new TypeError('authorization creation differs from its original decision');
  } else if (request.method === 'authorization.revoke' && data.method === request.method) {
    if (data.grant.grantId !== request.grantId || (data.disposition === 'already_consumed' ? data.grant.state !== 'consumed' : data.grant.state !== 'revoked'))
      throw new TypeError('authorization revocation differs from original grant');
  } else if (request.method === 'session.get' && data.method === request.method) {
    if (data.snapshot.session.id !== request.sessionId) throw new TypeError('Session page differs from request');
    contiguous(data.items, request.afterItemSeq!, data.highWaterItemSeq, request.limit!, data.nextItemSeq, item => item.itemSeq);
  } else if (request.method === 'run.get' && data.method === request.method) {
    if (data.snapshot.run.id !== request.runId || data.journal.some(entry => entry.runId !== request.runId) ||
        data.checkpoints.some(checkpoint => checkpoint.runId !== request.runId)) throw new TypeError('Run page differs from request');
    contiguous(data.items, request.afterItemSeq!, data.highWaterItemSeq, request.itemLimit!, data.nextItemSeq, item => item.itemSeq);
    contiguous(data.journal, request.afterJournalSeq!, data.highWaterJournalSeq, request.journalLimit!, data.nextJournalSeq, entry => entry.seq);
    const high = checkpointPosition(data.highWaterCheckpointCursor, request.runId);
    let previous = request.checkpointCursor === undefined ? undefined : checkpointPosition(request.checkpointCursor, request.runId);
    if ((previous && compareCheckpoint(previous, high) > 0) || data.checkpoints.length > request.checkpointLimit!) throw new TypeError('Checkpoint page exceeds its requested interval');
    for (const checkpoint of data.checkpoints) {
      const current = { createdAt: checkpoint.createdAt, checkpointId: checkpoint.id };
      if ((previous && compareCheckpoint(previous, current) >= 0) || compareCheckpoint(current, high) > 0) throw new TypeError('Checkpoint page is out of order');
      previous = current;
    }
    const next = data.nextCheckpointCursor === undefined ? undefined : checkpointPosition(data.nextCheckpointCursor, request.runId);
    if ((previous === undefined) !== (next === undefined) || (previous && next && compareCheckpoint(previous, next) !== 0))
      throw new TypeError('Checkpoint page did not retain its exact next cursor');
  } else if (request.method === 'run.attach' && data.method === request.method) {
    if (data.snapshot.run.id !== request.runId || request.afterEventSeq < data.earliestRetainedEventSeq - 1)
      throw new TypeError('event page differs from its requested retained interval');
    contiguous(data.events, request.afterEventSeq, data.highWaterEventSeq, request.limit!, data.nextEventSeq, event => event.eventSeq);
  }
  return response as InstalledControlResponseFor<M>;
}
function decodeInstalledControlError(value: unknown, method: InstalledControlMethod): InstalledControlErrorV1 {
  json(value);
  const error = value as Record<string, unknown>;
  const code = controlWireText(error?.code), base = ['schemaVersion', 'code', 'retryable', 'messageCode'];
  const extra = code === 'INVALID_REQUEST' ? ['issues'] : code === 'INTERNAL' ? ['errorId'] :
    code === 'INCOMPATIBLE_PROTOCOL' ? ['supportedControlRange', 'supportedHeadlessRange', 'upgradeAction'] :
    code === 'RATE_LIMITED' ? ['retryAfterMs'] : code === 'RESOURCE_EXHAUSTED' ? ['resourceKind', 'retryAfterMs'] :
    code === 'RESULT_UNAVAILABLE' ? ['runId', 'status', ...(error.retryable === true ? ['currentRevision'] : ['terminalDetailRef'])] :
    code === 'REVISION_CONFLICT' ? ['currentRevision', 'conflict'] : code === 'EVENT_CURSOR_EXPIRED' ? ['earliestEventSeq', 'latestEventSeq', 'snapshot'] :
    code === 'AUTHORIZATION_REQUIRED' && Object.hasOwn(error, 'requiredAuthorization') ? ['requiredAuthorization', 'errorId'] : [];
  controlWireRecord(error, [...base, ...extra]);
  if (error.schemaVersion !== 1) throw new TypeError('invalid control error schema');
  controlWireText(error.messageCode);
  if (code === 'REVISION_CONFLICT') {
    if (error.retryable !== true || !['run.submit', 'run.cancel', 'run.approve', 'run.input', 'run.reconcile', 'session.fork', 'session.compact', 'session.handoff.create'].includes(method)) throw new TypeError('unexpected revision conflict');
    const conflict = controlWireRecord(error.conflict, ['resourceKind', 'currentSnapshot']), revision = controlWireInteger(error.currentRevision, 1);
    if (conflict.resourceKind === 'session' && ['run.submit', 'session.fork', 'session.compact', 'session.handoff.create'].includes(method)) {
      if (sessionSnapshot(conflict.currentSnapshot).session.contextRevision !== revision) throw new TypeError('Session conflict revision differs');
    } else if (conflict.resourceKind === 'run' && (method === 'run.cancel' || method === 'run.approve' || method === 'run.input' || method === 'run.reconcile')) {
      if (runSnapshot(conflict.currentSnapshot).run.revision !== revision) throw new TypeError('Run conflict revision differs');
    } else throw new TypeError('invalid conflict resource');
  } else if (code === 'EVENT_CURSOR_EXPIRED') {
    if (method !== 'run.attach' || error.retryable !== false) throw new TypeError('unexpected expired event cursor');
    controlWireInteger(error.latestEventSeq, controlWireInteger(error.earliestEventSeq, 1)); runSnapshot(error.snapshot);
  } else if (code === 'RESULT_UNAVAILABLE') {
    if (method !== 'run.result' && method !== 'run.diff') throw new TypeError('unexpected result refusal');
    controlWireText(error.runId);
    if (error.retryable === true && ['queued', 'running', 'waiting'].includes(error.status as string)) controlWireInteger(error.currentRevision, 1);
    else if (error.retryable === false && ['failed', 'cancelled'].includes(error.status as string)) controlWireRef(error.terminalDetailRef);
    else throw new TypeError('invalid result refusal lifecycle');
  } else if (code === 'RATE_LIMITED' || code === 'RESOURCE_EXHAUSTED') {
    if (method === 'session.list' && code === 'RATE_LIMITED') {
      if (error.retryable !== true || error.retryAfterMs !== 1000 || error.messageCode !== 'control.list_cut_busy') throw new TypeError('invalid list preparation backpressure');
    } else if (method === 'session.list' && code === 'RESOURCE_EXHAUSTED') {
      if (error.retryable !== true || error.retryAfterMs !== 1000 || error.resourceKind !== 'state_storage' || error.messageCode !== 'control.list_cut_capacity') throw new TypeError('invalid list cut capacity refusal');
    } else if (error.retryable !== true || error.retryAfterMs !== 1000 || (method !== 'run.submit' &&
        !(method === 'run.apply' && code === 'RESOURCE_EXHAUSTED') && (code !== 'RATE_LIMITED' || method !== 'credential.finalize')) ||
        (code === 'RATE_LIMITED' ? error.messageCode !== 'run.credential_scope_busy' : error.messageCode !== 'run.queue_capacity' || error.resourceKind !== 'run_queue'))
      throw new TypeError('invalid fixed capacity refusal');
  } else {
    if (error.retryable !== false) throw new TypeError('invalid control refusal retryability');
    if (code === 'AUTHORIZATION_REQUIRED' && Object.hasOwn(error, 'requiredAuthorization')) {
      if (method !== 'run.submit' || error.messageCode !== 'dependency_script_authorization_required') throw new TypeError('unexpected dependency script consent request');
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(controlWireText(error.errorId))) throw new TypeError('invalid dependency consent correlation');
      decodeDependencyInstallScriptsDecision(error.requiredAuthorization);
    } else if (code === 'INVALID_REQUEST') {
      if (!Array.isArray(error.issues) || error.issues.length > 1000) throw new TypeError('invalid control issues');
      for (const issue of error.issues) {
        const data = controlWireRecord(issue, ['path', 'issueCode']); controlWireText(data.path, 4096); controlWireText(data.issueCode);
      }
    } else if (code === 'INTERNAL') {
      const errorId = controlWireText(error.errorId);
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(errorId)) throw new TypeError('invalid internal error identity');
    } else if (code === 'INCOMPATIBLE_PROTOCOL') {
      const control = decodeControlRange(error.supportedControlRange); decodeControlRange(error.supportedHeadlessRange);
      if (control.min !== 1 || control.max !== 1 || !['upgrade_client', 'upgrade_supervisor'].includes(error.upgradeAction as string))
        throw new TypeError('invalid control incompatibility');
    } else if (!['NOT_FOUND', 'AUTHORIZATION_REQUIRED', 'ARTIFACT_MISMATCH', 'UNSUPPORTED_PLATFORM', 'REQUEST_ID_CONFLICT',
      'ADMISSION_KEY_CONFLICT', 'MODEL_COST_UNKNOWN', 'BUDGET_EXHAUSTED', 'CANCEL_REQUESTED', 'RUN_TERMINAL', 'UNSUPPORTED_EXECUTION_IDENTITY'].includes(code))
      throw new TypeError('unknown installed control refusal');
  }
  return error as InstalledControlErrorV1;
}

/** Schema 3 wraps the original closed application object. It never supplies
 * identity, time, execution or a second Run lifecycle. */
export type HeadlessControlRequestV3 = Readonly<{ schemaVersion: 3; request: InstalledControlRequestV1 }>;
export type HeadlessControlResponseV3 = Readonly<{ schemaVersion: 3; protocolVersion: 1;
  type: 'response'; response: InstalledControlResponseV1 }>;
export type HeadlessRunEventV3 = RunEvent extends infer E ? E extends RunEvent ? Readonly<{
  schemaVersion: 3; protocolVersion: 1; type: E['kind']; runId: string; eventSeq: number; timestamp: string;
  payload: Omit<E, 'schemaVersion' | 'kind' | 'runId' | 'eventSeq' | 'occurredAt'>
}> : never : never;
export type HeadlessControlRecordV3 = HeadlessControlResponseV3 | HeadlessRunEventV3;

export function decodeHeadlessControlRequest(value: unknown): HeadlessControlRequestV3 {
  json(value); assertBoundedJsonValue(value, 'headless request');
  const data = controlWireRecord(value, ['schemaVersion', 'request']);
  if (data.schemaVersion !== HEADLESS_SCHEMA_VERSION || canonicalJsonBytes(data).length > CONTROL_FRAME_BYTES)
    throw new TypeError('headless request requires bounded schema 3');
  return immutableSnapshot({ schemaVersion: 3, request: decodeInstalledControlRequest(data.request) });
}

export function headlessControlResponse<M extends InstalledControlMethod>(value: unknown,
  request: Extract<InstalledControlRequestV1, { method: M }>): HeadlessControlResponseV3 {
  const response = decodeInstalledControlResponse(value, request);
  const record = { schemaVersion: 3 as const, protocolVersion: 1 as const, type: 'response' as const, response };
  assertBoundedJsonValue(record, 'headless response');
  if (canonicalJsonBytes(record).length > CONTROL_FRAME_BYTES) throw new TypeError('headless response exceeds its bound');
  return immutableSnapshot(record);
}

export function decodeHeadlessControlResponse(value: unknown): HeadlessControlResponseV3 {
  json(value); assertBoundedJsonValue(value, 'headless response');
  const data = controlWireRecord(value, ['schemaVersion', 'protocolVersion', 'type', 'response']);
  if (data.schemaVersion !== 3 || data.protocolVersion !== 1 || data.type !== 'response' ||
      canonicalJsonBytes(data).length > CONTROL_FRAME_BYTES) throw new TypeError('headless response requires bounded schema 3');
  const response = data.response as Record<string, any> | null;
  const method = response?.ok === true ? response.result?.method : response?.method;
  if (!CONTROL_METHODS_V1.includes(method)) throw new TypeError('unknown headless response method');
  return immutableSnapshot({ schemaVersion: 3, protocolVersion: 1, type: 'response',
    response: decodeInstalledControlEnvelope(response, method) });
}

/** Frontend negotiation is a projection of the already authenticated hello,
 * never another peer observation or permission grant. */
export function headlessControlHello(supplied: ControlHelloRequestV1,
  actual: InstalledControlResultFor<'control.hello'>): HeadlessControlResponseV3 {
  const request = decodeControlHelloRequest(supplied);
  const response = decodeInstalledControlEnvelope({ protocolVersion: 1, ok: true, result: actual }, 'control.hello');
  if (!response.ok) throw new TypeError('headless hello requires the authenticated result');
  const available = response.result;
  if (!rangeOverlap(request.controlSchemaRange, available.controlSchemaRange) ||
      !rangeOverlap(request.headlessSchemaRange, { min: 3, max: 3 }) ||
      !rangeOverlap(available.headlessSchemaRange, { min: 3, max: 3 }))
    return headlessControlResponse({ protocolVersion: 1, ok: false, method: 'control.hello', error: {
      schemaVersion: 1, code: 'INCOMPATIBLE_PROTOCOL', retryable: false, messageCode: 'control.incompatible_protocol',
      supportedControlRange: available.controlSchemaRange,
      supportedHeadlessRange: rangeOverlap(available.headlessSchemaRange, { min: 3, max: 3 })
        ? { min: 3, max: 3 } : available.headlessSchemaRange,
      upgradeAction: request.headlessSchemaRange.max < 3 ? 'upgrade_client' : 'upgrade_supervisor'
    } }, request);
  return headlessControlResponse({ protocolVersion: 1, ok: true, result: { ...available,
    headlessSchemaRange: { min: 3, max: 3 },
    enabledFeatureIds: request.requestedFeatureIds.filter(feature => available.enabledFeatureIds.includes(feature)) } }, request);
}

/** Exact presentation of one decoded committed event, never a Run snapshot. */
export function headlessRunEvent(value: unknown): HeadlessRunEventV3 {
  json(value); assertBoundedJsonValue(value, 'headless event');
  const event = decodeWireEvent(value);
  const { schemaVersion: _schema, kind, runId, eventSeq, occurredAt, ...payload } = event;
  const record = { schemaVersion: 3 as const, protocolVersion: 1 as const, type: kind, runId, eventSeq,
    timestamp: occurredAt, payload };
  if (canonicalJsonBytes(record).length > CONTROL_FRAME_BYTES) throw new TypeError('headless event exceeds its bound');
  return immutableSnapshot(record) as HeadlessRunEventV3;
}

export function decodeHeadlessControlRecord(value: unknown): HeadlessControlRecordV3 {
  json(value); assertBoundedJsonValue(value, 'headless record');
  if ((value as { type?: unknown } | null)?.type === 'response') return decodeHeadlessControlResponse(value);
  const data = controlWireRecord(value, ['schemaVersion', 'protocolVersion', 'type', 'runId', 'eventSeq', 'timestamp', 'payload']);
  if (data.schemaVersion !== 3 || data.protocolVersion !== 1 || !['state_changed', 'progress'].includes(data.type as string))
    throw new TypeError('invalid schema3 event record');
  const payload = data.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new TypeError('invalid schema3 event payload');
  if (Object.keys(payload).some(key => ['schemaVersion', 'kind', 'runId', 'eventSeq', 'occurredAt'].includes(key)))
    throw new TypeError('event payload cannot substitute its envelope');
  return headlessRunEvent({ ...payload, schemaVersion: 1, kind: data.type, runId: data.runId,
    eventSeq: data.eventSeq, occurredAt: data.timestamp });
}
