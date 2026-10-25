import type { Stats } from 'node:fs';
import { lstat, mkdir, readdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';

import {
  KERNEL_CAS_DIRECTORY,
  KERNEL_DATABASE_FILENAME,
  KERNEL_SQLITE_APPLICATION_ID,
  KERNEL_STATE_SCHEMA_VERSION
} from '../config.js';
import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { checkCanonicalBytes, validateBundle, validateTrustStore } from './installed-artifacts.js';
import { decodeEndpointAuthorityCommandCore, decodeEndpointAuthorityOperation, decodeEndpointAuthorityRecord,
  decodeEndpointRegistration, decodeCredentialAuthorityCommandCore, decodeCredentialAuthorityOperation, decodeCredentialAuthorityRecord,
  decodeCredentialAuthorityRevokeCommandCore, decodeCredentialAuthorityRevokeOperation,
  decodeEndpointCredentialGrantBinding, type EndpointCredentialGrantBinding,
  type CredentialAuthorityCommandCoreV1, type CredentialAuthorityOperationV1, type CredentialPurpose,
  type EndpointAuthorityCommandCoreV1, type EndpointAuthorityOperationV1, type EndpointAuthorityRecordV1,
  type EndpointRegistrationV1, type CredentialAuthorityRecordV1, type CredentialAuthorityRevokeOperationV1 } from '../kernel/credential-authority.js';
import {
  assertArtifactRef,
  assertRequestId,
  digestOmitting,
  encodeCanonicalTime,
  identityHash,
  normalizeAbsolutePath,
  parseCanonicalTime,
  requiredSafeInteger,
  sha256Bytes,
  unsignedDecimalId
} from '../kernel/identity.js';
import type {
  KernelGenerationIdentityV1,
  InvocationJournalEntry,
  LocalControlChannelIdentityV1,
  LocalPrincipalIdentityV1,
  PlatformProcessIdentityV1,
  RecoveryClosureV1,
  Run,
  Session,
  StateLockIdentityV1,
  StateOwnerAcquisitionEvidenceV1,
  StateOwnerRecordV1,
  StateOwnerTransitionEvidenceV1,
  StateRootIdentityV1
} from '../kernel/types.js';
import { ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import {
  insertGenesisTimeFence,
  readTimeFence,
  recoverRegressedTimeFence,
  sampleCanonicalNow,
  transferTimeFenceOwner,
  type TimeFenceAdvance
} from './canonical-time.js';
import { advanceTimeFence } from './canonical-time.js';
import { decodeSecretServiceObservation, decodeRetainedSecretServiceObservation,
  decodeSecretServiceSelector, type SecretServiceObservation, type SecretServiceSelector,
  type NativeCredentialInspection, type NativeCredentialPlatformBinding } from './credential-platform.js';
import { ensureInstalledCredentialSupervisor, type CredentialFinalizeRequest } from './installed-credential-client.js';
import { noteInstalledCredentialPhase } from './installed-diagnostics.js';
import { beginInstalledApplyDiagnostic, beginInstalledSubmitDiagnostic, beginInstalledSchedulerDiagnostic, installedRunDiagnosticsSubscribed,
  noteInstalledStoreStop, noteInstalledPublicationPhase, type InstalledApplyDiagnostic } from './installed-run-diagnostics.js';
import { ContentAddressedStore } from './cas.js';
import { openLocalControlListener, type AuthenticatedControlIdentity, type LocalControlConnection, type LocalControlListener } from './control-channel.js';
import { readControl, type ReadControlRequest } from './control-read.js';
import { CredentialFinalizationTimeError, InstalledModelAuthorizationError, KernelStorageError, ResourceRetirementError, RunTerminalError } from './errors.js';
import { assertInstalledCredentialScope, installedCredentialProvenance, observeInstalledCredentialProducer,
  type InstalledCredentialScope, type InstalledCredentialProvenance,
  withHeldInstalledRuntime, withInstalledWorkerRoot, readInstalledRuntimeObservation, type HeldInstalledAnchor,
  type HeldInstalledRuntime, type InstalledRuntimeBorrow, type InstalledRuntimeObservation } from './installed-runtime.js';
import { CredentialScopeBusyError, withCredentialAuthorityLock, loadInstalledCredentialPlatform, loadInstalledModelBroker } from './installed-runtime.js';
import { MODEL_BROKER_ENTRY_ID, InstalledModelBrokerRefusalError, type NativeModelTransport, type ModelBrokerBinding, type ModelBrokerClosed } from './model-broker-native.js';
import { decodeBrokerInvocationAmbiguity, type BrokerInvocationAmbiguityEvidenceV1 } from '../kernel/broker-ambiguity.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { selectInstalledModelProgress } from './installed-model-progress.js';
import { assertInstalledRunAdmissionCapacity, INSTALLED_RUN_INVENTORY_LIMIT } from './installed-run-capacity.js';
import type { SupervisorHelloV1, SupervisorStatusV1 } from './installed-control.js';
import { assertStateOwnerLock, loadNativeStateOwner, stateRootIdentityFromDescriptor, type HeldStateOwnerLock, type NativeStateOwner } from './native-owner.js';
import {
  decodeControlChannel,
  decodeLocalPrincipalIdentity,
  decodePlatformProcessIdentity,
  decodeStateLockIdentity,
  decodeStateRootIdentity
} from './decoders.js';
import { admitRun, type AdmitRunInput, type AdmitRunResult } from './reducers/admission.js';
import { AgentContextExhaustedError, loadAgentRun, type LoadAgentRunInput } from './reducers/agent.js';
import {
  abandonUnknownInvocation,
  claimInvocationDispatch,
  completeInvocation,
  failClaimedInvocationWithoutRelease,
  failInvocationBeforeDispatch,
  markInvocationUnknown,
  markInstalledBrokerAmbiguity,
  readModelClaimCut, assertLiveDispatchState, requireHealthyFence,
  prepareInvocation,
  type ClaimInvocationDispatchInput,
  type PrepareInvocationInput,
  type SettleInvocationInput
} from './reducers/invocation.js';
import { createInstalledSession, createSession, type CreateSessionInput, type CreateSessionResult } from './reducers/session.js';
import {
  activateWorkerLease,
  beginGenerationCheckpoint,
  beginGenerationRevocation,
  recordWorkerPreactivated,
  renewWorkerLease,
  reserveWorkerLaunch,
  sealWorkerGeneration,
  type ActivateWorkerLeaseInput,
  type BeginGenerationCheckpointInput,
  type BeginGenerationRevocationInput,
  type RecordWorkerPreactivatedInput,
  type RenewWorkerLeaseInput,
  type ReserveWorkerLaunchInput,
  type SealWorkerGenerationInput
} from './reducers/worker-launch.js';
import {
  recordWorkspaceGenerationPreactivated,
  registerWorkspaceGeneration,
  type RecordWorkspaceGenerationPreactivatedInput,
  type RegisterWorkspaceGenerationInput
} from './reducers/workspace-transition.js';
import { readDeliveryPublicationClosure, readRecoveryClosure } from './recovery-closure.js';
import { readVerifierProgress } from './verifier-recovery.js';
import { verifierOperationId } from './verifier-policy.js';
import type { RunResultPhase } from './run-result.js';
import { beginWorkerRecovery, beginWorkerRecoveryProbe, closeWorkerRecoveryProbe, type BeginWorkerRecoveryInput } from './reducers/worker-recovery.js';
import { readRun, readSession, readSessionPrincipalId } from './rows.js';
import { applyKernelSchema, assertPristineKernelSchema, KERNEL_AUTHORITY_TABLES, KERNEL_SCHEMA_SQL, readSchemaUserVersion } from './schema.js';
import { iterateNodeSqliteStatement, openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import {
  assertActiveStateOwner,
  assertContiguousStateOwnerHistory,
  contextFromStateOwner,
  gracefullyReleaseStateOwner,
  readActiveStateOwner,
  readLatestStateOwner,
  insertStateOwnerArtifacts,
  terminalStateOwnerRecord,
  type StateOwnerContext
} from './state-owner.js';
import { hostPlatform } from './workspace-identity.js';
import { readRetainedStateOwnerHistory, readRetainedStateOwnerProcess as readStateOwnerProcess } from './state-owner-history.js';
import { immutableSnapshot } from '../model/immutable.js';
import { loadRunExecution, type LoadRunExecutionInput, type RunExecutionInstallation, type RunRetirementPhase, type RunPublicationPhase } from './run-execution.js';
import { retireAbandonedPreactivations } from './preactivation-retirement.js';
import { exactKeys, verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { SandboxProfileV1, SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { normalizeRunSubmitRequest, runSubmitIntentDigest, normalizeSourceInspectionRequest, sourceInspectionIntentDigest } from './source-target.js';
import { normalizeRunApplyRequest } from '../kernel/control-apply.js';
import { decodeInstalledControlRequest } from '../kernel/control-wire.js';
import { readVerifiedDeliverySource } from './delivery-source-authority.js';
import { admitInstalledDelivery, prepareInstalledDelivery, replayInstalledDeliveryAdmission, type AdmitDeliveryResult } from './reducers/delivery-admission.js';
import { loadDeliveryContinuation, type DeliveryContinuation } from './run-continuation.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { assertCurrentControlFrame, validateControlChannelClosure } from './control-channel.js';
import { readHighestPreparedAttempt, readInvocationAttempt, readOperationJournal } from './repositories/journal.js';
import { assertModelGrantDispatch } from './model-grant.js';
import { readCheckpoint } from './rows.js';
import { decodeRunSpec } from './decoders.js';
import type { AgentRunState } from './reducers/agent.js';
import type { RunAssemblyValidationMaterial } from '../model/run-assembly.js';
import type { ModelAttemptResult } from '../model/model-session.js';
import type { RunExecution } from './run-execution.js';
import { installedSandboxProfile } from './installed-sandbox-profile.js';

const SMALL_BYTES = 1_048_576;
const TRUST_BYTES = 16 * SMALL_BYTES;
type InstalledContinuation = AgentRunState | DeliveryContinuation;
// Integration gate, not a test override. Enable only when the same production
// owner also implements no-op projection and claimed publication Stop drain.
// Connected for the fixed supported Linux recipe; unsupported input contracts
// still refuse at admission. This is not installed or release qualification.
const INSTALLED_DELIVERY_COMPOSITION_COMPLETE = true;

/** Physical authority-store scope, not an authenticated channel or credential
 * grant. Its SQL, data descriptors, URI and retirement never escape. */
export type HeldCredentialAuthorityLock = Readonly<{ assertHeld(): void }>;
type CredentialBinding = InstalledCredentialProvenance & { physical: InstalledCredentialScope; active: boolean;
  lastCommittedAt?: string;
  database?: DatabaseSync };
const credentialTokens = new WeakMap<HeldCredentialAuthorityLock, CredentialBinding>();

function checkedCredentialToken(token: HeldCredentialAuthorityLock): CredentialBinding {
  const held = credentialTokens.get(token);
  if (!held || !held.active) throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential authority token is invalid or its callback has ended');
  assertInstalledCredentialScope(held.physical);
  return held;
}

function frozenModelCredential(record: CredentialAuthorityRecordV1): EndpointCredentialGrantBinding {
  const { state: _state, platformItem: _item, recordDigest: _digest, revokedAt: _revoked,
    revokedByRequestId: _request, revokedByRequestDigest: _requestDigest, ...body } = record;
  return decodeEndpointCredentialGrantBinding({ ...body, bindingDigest: canonicalSha256(body) });
}
function readStoredCredentialObservation(held: CredentialBinding, operation: CredentialAuthorityOperationV1): SecretServiceObservation {
  const observed = readCredentialFacts(held, operation.requestId).find(fact =>
    fact.operation.attempt === operation.attempt && fact.operation.phase === 'secret_stored')?.observation;
  if (!observed) throw new KernelStorageError('ARTIFACT_MISMATCH', 'model credential has no original actual platform-store observation');
  return observed;
}
function currentModelAuthority(held: CredentialBinding, principalId: string, endpointId: string,
  credentialIds: readonly string[], now: string, frozen?: { endpoint: EndpointRegistrationV1; bindings: readonly EndpointCredentialGrantBinding[] }) {
  if (held.ownerPrincipalId !== principalId || credentialIds.length !== 1)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed model recipe requires its exact owner and one frozen bearer credential');
  const endpoint = readEndpointHistory(held, endpointId).at(-1);
  if (!endpoint || endpoint.state !== 'active' || !endpoint.registration.purposes.includes('model_endpoint') ||
      endpoint.registration.createdAt > now || endpoint.createdAt > now)
    throw new InstalledModelAuthorizationError();
  const history = readCredentialHistory(held, credentialIds[0]!), record = history.latest, creating = history.creating;
  if (!record || !creating || record.state !== 'active' || record.purpose !== 'model_endpoint' ||
      record.createdAt > now || (record.expiresAt !== undefined && now >= record.expiresAt) ||
      record.endpointRegistrationRef !== endpoint.expectedRegistrationArtifactRef ||
      record.endpointIdentityDigest !== endpoint.registration.endpointIdentityDigest || record.tlsPolicyDigest !== endpoint.registration.tlsPolicyDigest)
    throw new InstalledModelAuthorizationError();
  const binding = frozenModelCredential(record);
  if (frozen && (canonicalSha256(frozen.endpoint) !== endpoint.expectedRegistrationArtifactRef ||
      frozen.bindings.length !== 1 || canonicalSha256(frozen.bindings[0]) !== canonicalSha256(binding)))
    throw new InstalledModelAuthorizationError();
  assertInstalledCredentialScope(held.physical);
  return { endpoint: endpoint.registration, bindings: [binding], creating,
    selector: credentialSelector(held, creating), observation: readStoredCredentialObservation(held, creating) };
}

/** An authenticated v1 store contains endpoints only. Verify its exact format
 * before returning absence; an unknown schema must never look credential-free.
 * This metadata read does not load a platform store or acquire StateOwner. */
export function readCredentialAuthority(token: HeldCredentialAuthorityLock, credentialGrantId: string): CredentialAuthorityRecordV1 | null {
  const held = checkedCredentialToken(token);
  try {
    if (typeof credentialGrantId !== 'string' || !credentialGrantId ||
        normalizeCanonicalText(credentialGrantId) !== credentialGrantId || Buffer.byteLength(credentialGrantId) > SMALL_BYTES)
      throw new TypeError('invalid credential id');
  } catch (cause) { throw new KernelStorageError('INVALID_REQUEST', 'credential id must be bounded nonempty canonical text', { cause }); }
  ensureEndpointSchema(held.database!);
  const latest = credentialSchemaVersion(held.database!) === 1 ? null : readCredentialHistory(held, credentialGrantId).latest ?? null;
  assertInstalledCredentialScope(held.physical);
  return latest && immutableSnapshot(latest);
}

export type CredentialWriteRequest = Readonly<{ schemaVersion: 1; requestId: string;
  credentialGrantId: string; secretSubmissionId: string; expiresAt?: string } & (
  | { kind: 'enroll'; purpose: CredentialPurpose; endpointRegistrationId: string }
  | { kind: 'rotate'; expectedAuthorityRevision: number })>;
export function decodeCredentialWriteRequest(input: unknown): CredentialWriteRequest {
  const value = input as Record<string, unknown>;
  const keys = ['schemaVersion', 'kind', 'requestId', 'credentialGrantId', 'secretSubmissionId',
    ...(value?.kind === 'enroll' ? ['purpose', 'endpointRegistrationId'] : ['expectedAuthorityRevision'])];
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || value.schemaVersion !== 1 || !['enroll', 'rotate'].includes(value.kind as string) ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string' || ![...keys, 'expiresAt'].includes(key)) ||
      keys.some(key => !Object.hasOwn(value, key))) throw new TypeError('invalid credential write metadata');
  for (const key of ['requestId', 'credentialGrantId', 'secretSubmissionId', ...(value.kind === 'enroll' ? ['endpointRegistrationId'] : [])]) {
    const text = value[key];
    if (typeof text !== 'string' || !text || text.includes('\0') || normalizeCanonicalText(text) !== text ||
        Buffer.byteLength(text) > (key === 'endpointRegistrationId' ? 4096 : 256)) throw new TypeError('invalid credential write id');
  }
  assertRequestId(value.requestId as string);
  if (value.kind === 'enroll') {
    if (!['model_endpoint', 'dependency_registry', 'mcp_streamable_http'].includes(value.purpose as string)) throw new TypeError('invalid credential purpose');
  } else if (!Number.isSafeInteger(value.expectedAuthorityRevision) || (value.expectedAuthorityRevision as number) < 1 ||
      (value.expectedAuthorityRevision as number) >= Number.MAX_SAFE_INTEGER) throw new TypeError('invalid credential expected revision');
  if (Object.hasOwn(value, 'expiresAt')) {
    if (typeof value.expiresAt !== 'string') throw new TypeError('invalid credential expiry');
    parseCanonicalTime(value.expiresAt);
  }
  return immutableSnapshot(value as CredentialWriteRequest);
}

export type CredentialRevokeRequest = Readonly<{ schemaVersion: 1; kind: 'revoke'; requestId: string;
  credentialGrantId: string; expectedAuthorityRevision: number }>;
export function decodeCredentialRevokeRequest(input: unknown): CredentialRevokeRequest {
  const value = input as Record<string, unknown>, keys = ['schemaVersion', 'kind', 'requestId', 'credentialGrantId', 'expectedAuthorityRevision'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      value.schemaVersion !== 1 || value.kind !== 'revoke' || Reflect.ownKeys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) throw new TypeError('invalid credential revocation metadata');
  for (const key of ['requestId', 'credentialGrantId']) {
    const text = value[key];
    if (typeof text !== 'string' || !text || text.includes('\0') || normalizeCanonicalText(text) !== text || Buffer.byteLength(text) > 256)
      throw new TypeError('invalid credential revocation id');
  }
  assertRequestId(value.requestId as string);
  if (!Number.isSafeInteger(value.expectedAuthorityRevision) || (value.expectedAuthorityRevision as number) < 1)
    throw new TypeError('invalid credential expected revision');
  return immutableSnapshot(value as CredentialRevokeRequest);
}

export type CredentialCleanupRequest = Readonly<{ schemaVersion: 1; kind: 'cleanup'; requestId: string }>;
export function decodeCredentialCleanupRequest(input: unknown): CredentialCleanupRequest {
  const value = input as Record<string, unknown>, keys = ['schemaVersion', 'kind', 'requestId'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) || value.schemaVersion !== 1 || value.kind !== 'cleanup' ||
      typeof value.requestId !== 'string' || !value.requestId || normalizeCanonicalText(value.requestId) !== value.requestId ||
      Buffer.byteLength(value.requestId) > 256) throw new TypeError('invalid credential cleanup metadata');
  assertRequestId(value.requestId);
  return immutableSnapshot(value as CredentialCleanupRequest);
}

type CredentialFact = { operation: CredentialAuthorityOperationV1; observation?: SecretServiceObservation };
function credentialSchemaVersion(database: DatabaseSync): number { return Number(database.prepare('PRAGMA user_version').get()?.user_version); }
function ensureCredentialSchema(database: DatabaseSync): void {
  ensureEndpointSchema(database);
  if (credentialSchemaVersion(database) === 2) return;
  // One atomic extension. Existing endpoint/provenance BLOBs are not copied,
  // reserialized or rebuilt, and there is no secondary request journal.
  endpointTransaction(database, () => database.exec(`
    CREATE TABLE credential_records(owner_principal_id TEXT NOT NULL, credential_grant_id TEXT NOT NULL,
      authority_revision INTEGER NOT NULL CHECK(authority_revision>0), record_json TEXT NOT NULL,
      PRIMARY KEY(owner_principal_id,credential_grant_id,authority_revision)) STRICT;
    CREATE TABLE credential_operation_facts(owner_principal_id TEXT NOT NULL, request_id TEXT NOT NULL,
      credential_grant_id TEXT NOT NULL, attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
      phase_rank INTEGER NOT NULL CHECK(phase_rank BETWEEN 0 AND 2), operation_json TEXT NOT NULL,
      platform_observation_json TEXT,
      CHECK((phase_rank=1)=(platform_observation_json IS NOT NULL)),
      PRIMARY KEY(owner_principal_id,request_id,attempt,phase_rank)) STRICT;
    CREATE INDEX credential_grant_operations ON credential_operation_facts(owner_principal_id,credential_grant_id);
    CREATE INDEX credential_creating_operations ON credential_operation_facts(owner_principal_id,credential_grant_id,
      json_extract(operation_json,'$.intendedAuthorityRevision'))
      WHERE phase_rank=2 AND json_extract(operation_json,'$.phase')='committed';
    CREATE TABLE credential_revoke_operations(owner_principal_id TEXT NOT NULL, request_id TEXT NOT NULL,
      operation_json TEXT NOT NULL, cleanup_observation_json TEXT,
      PRIMARY KEY(owner_principal_id,request_id)) STRICT;
    PRAGMA user_version=2;
  `));
}
function credentialSelector(held: CredentialBinding, operation: CredentialAuthorityOperationV1): SecretServiceSelector {
  if (operation.platformItem.kind !== 'linux_secret_service') throw new TypeError('credential item is not Linux Secret Service');
  return { itemId: operation.platformItem.itemId, ownerPrincipalId: held.ownerPrincipalId,
    stateRootIdentityDigest: held.rootIdentity.identityDigest, creatingOperationId: operation.operationId,
    credentialGrantId: operation.credentialGrantId, secretGeneration: operation.intendedSecretGeneration,
    credentialTargetDigest: operation.credentialTargetDigest };
}
function retainedCredentialChannel(held: CredentialBinding, operation: CredentialAuthorityOperationV1 | CredentialAuthorityRevokeOperationV1) {
  const object = (ref: string) => checkCanonicalBytes(endpointObject(held, ref));
  const channel = decodeControlChannel(object(operation.channelIdentityRef));
  const principal = decodeLocalPrincipalIdentity(object(channel.principalIdentityRef));
  const root = decodeStateRootIdentity(object(principal.stateRootIdentityRef));
  if (channel.transport.kind !== 'in_process') throw new TypeError('credential preparation channel is not local auth');
  const processIdentity = decodePlatformProcessIdentity(object(channel.transport.processIdentityRef));
  if (channel.client !== 'cli' || channel.channelIdentityDigest !== operation.channelIdentityDigest ||
      channel.principalId !== held.ownerPrincipalId || principal.principalId !== held.ownerPrincipalId ||
      principal.identityDigest !== channel.principalIdentityDigest || principal.stateRootIdentityDigest !== root.identityDigest ||
      canonicalSha256(root) !== canonicalSha256(held.rootIdentity) || principal.platform !== root.platform ||
      principal.effectiveUid !== root.ownerUid || processIdentity.platform !== root.platform || processIdentity.ownerUid !== root.ownerUid ||
      processIdentity.identityDigest !== channel.transport.processIdentityDigest ||
      processIdentity.executableImageDigest !== held.processIdentity.executableImageDigest || processIdentity.observedAt !== channel.openedAt ||
      parseCanonicalTime('metadataCommittedAt' in operation ? operation.metadataCommittedAt : operation.createdAt) < parseCanonicalTime(channel.openedAt) ||
      ('finishedAt' in operation && operation.finishedAt !== undefined && parseCanonicalTime(operation.finishedAt) < parseCanonicalTime(operation.createdAt)))
    throw new TypeError('credential preparation provenance differs');
  return { channel, processIdentity };
}
function credentialEndpoint(held: CredentialBinding, core: CredentialAuthorityCommandCoreV1): EndpointRegistrationV1 {
  const registration = decodeEndpointRegistration(checkCanonicalBytes(endpointObject(held, core.endpointRegistrationRef)));
  if (registration.ownerPrincipalId !== held.ownerPrincipalId || !registration.purposes.includes(core.purpose) ||
      registration.endpointIdentityDigest !== core.endpointIdentityDigest || registration.tlsPolicyDigest !== core.tlsPolicyDigest ||
      parseCanonicalTime(core.externalSubject.observedAt) < parseCanonicalTime(registration.createdAt))
    throw new TypeError('credential endpoint closure differs');
  verifyEndpointTrust(held, registration, true);
  return registration;
}
function readCredentialFacts(held: CredentialBinding, requestId: string): CredentialFact[] {
  if (credentialSchemaVersion(held.database!) === 1) return [];
  const rows = held.database!.prepare(`SELECT credential_grant_id,attempt,phase_rank,operation_json,platform_observation_json
    FROM credential_operation_facts WHERE owner_principal_id=? AND request_id=? ORDER BY attempt,phase_rank LIMIT 10`)
    .all(held.ownerPrincipalId, requestId);
  if (rows.length > 9) throw new TypeError('credential request contains extra facts');
  const facts: CredentialFact[] = [];
  let prepared: CredentialAuthorityOperationV1 | undefined;
  let previous: CredentialAuthorityOperationV1 | undefined;
  for (const row of rows) {
    const operation = endpointJson(row.operation_json, decodeCredentialAuthorityOperation);
    const rank = operation.phase === 'prepared' ? 0 : operation.phase === 'secret_stored' ? 1 : 2;
    if (operation.ownerPrincipalId !== held.ownerPrincipalId || operation.requestId !== requestId ||
        operation.credentialGrantId !== row.credential_grant_id || operation.attempt !== row.attempt || rank !== row.phase_rank)
      throw new TypeError('credential fact index differs');
    retainedCredentialChannel(held, operation); credentialEndpoint(held, operation.commandCore);
    if (parseCanonicalTime(operation.createdAt) < parseCanonicalTime(operation.commandCore.externalSubject.observedAt))
      throw new TypeError('credential preparation precedes its frozen subject');
    if (operation.phase === 'prepared') {
      if (operation.attempt !== (previous?.attempt ?? 0) + 1 || (previous && previous.phase !== 'aborted') ||
          (prepared && (!canonicalJsonBytes(prepared.commandCore).equals(canonicalJsonBytes(operation.commandCore)) ||
            prepared.intendedAuthorityRevision !== operation.intendedAuthorityRevision ||
            prepared.intendedSecretGeneration !== operation.intendedSecretGeneration)))
        throw new TypeError('credential attempts are not contiguous frozen-core attempts');
      prepared = operation;
    } else {
      if (!prepared || prepared.attempt !== operation.attempt ||
          (operation.phase === 'secret_stored' ? previous?.phase !== 'prepared'
            : operation.phase === 'committed' ? previous?.phase !== 'secret_stored'
            : previous?.phase !== 'prepared' && previous?.phase !== 'secret_stored'))
        throw new TypeError('credential phase continuity differs');
      const base = (value: CredentialAuthorityOperationV1) => {
        const { phase: _phase, operationDigest: _digest, committedAuthorityRevision: _revision,
          abortReason: _reason, finishedAt: _finished, ...body } = value; return body;
      };
      if (!canonicalJsonBytes(base(prepared)).equals(canonicalJsonBytes(base(operation))))
        throw new TypeError('credential transition rewrites its original preparation');
    }
    let observation: SecretServiceObservation | undefined;
    if (rank === 1) {
      observation = endpointJson(row.platform_observation_json, decodeRetainedSecretServiceObservation);
      if (observation.kind !== 'stored' || observation.bus.uid !== held.rootIdentity.ownerUid ||
          !canonicalJsonBytes(observation.selector).equals(canonicalJsonBytes(credentialSelector(held, operation))))
        throw new TypeError('credential platform provenance differs');
    } else if (row.platform_observation_json !== null) throw new TypeError('credential observation belongs to the wrong phase');
    facts.push({ operation, ...(observation ? { observation } : {}) }); previous = operation;
  }
  return facts;
}
function credentialCreatingOperation(held: CredentialBinding, record: CredentialAuthorityRecordV1): CredentialAuthorityOperationV1 {
  const rows = held.database!.prepare(`SELECT request_id,operation_json FROM credential_operation_facts
    WHERE owner_principal_id=? AND credential_grant_id=? AND phase_rank=2 AND json_extract(operation_json,'$.phase')='committed'
      AND json_extract(operation_json,'$.intendedAuthorityRevision')=? LIMIT 2`)
    .all(held.ownerPrincipalId, record.credentialGrantId, record.authorityRevision);
  if (rows.length !== 1 || typeof rows[0]!.request_id !== 'string') throw new TypeError('credential revision has no unique creating operation');
  const facts = readCredentialFacts(held, rows[0]!.request_id);
  const operation = facts.at(-1)?.operation;
  if (!operation || operation.phase !== 'committed' || canonicalJsonBytes(operation).toString('utf8') !== rows[0]!.operation_json ||
      operation.intendedAuthorityRevision !== record.authorityRevision || operation.intendedSecretGeneration !== record.secretGeneration ||
      operation.finishedAt !== record.createdAt || operation.commandCore.purpose !== record.purpose ||
      operation.commandCore.endpointRegistrationRef !== record.endpointRegistrationRef ||
      operation.commandCore.endpointIdentityDigest !== record.endpointIdentityDigest || operation.commandCore.tlsPolicyDigest !== record.tlsPolicyDigest ||
      operation.commandCore.expiresAt !== record.expiresAt || operation.intendedExternalSubjectDigest !== record.externalSubjectDigest ||
      !canonicalJsonBytes(operation.commandCore.externalSubject).equals(canonicalJsonBytes(record.externalSubject)) ||
      !canonicalJsonBytes(operation.platformItem).equals(canonicalJsonBytes(record.platformItem)))
    throw new TypeError('credential revision differs from its committed operation');
  return operation;
}
type CredentialCleanupFailure = Readonly<{ schemaVersion: 1; kind: 'cleanup_failure'; selector: SecretServiceSelector;
  stage: 'platform_load' | 'delete_known' | 'result_validation'; errorCode: 'platform_store_unavailable' | 'delete_denied' | 'delete_failed' }>;
type CredentialCleanupObservation = SecretServiceObservation | CredentialCleanupFailure;
type CredentialRevokeRow = { operation: CredentialAuthorityRevokeOperationV1; observation?: CredentialCleanupObservation };
function decodeCredentialCleanupObservation(value: unknown): CredentialCleanupObservation {
  const data = value as Record<string, unknown>;
  if (data?.kind !== 'cleanup_failure') {
    const actual = decodeRetainedSecretServiceObservation(value);
    if (!['absent', 'deleted'].includes(actual.kind)) throw new TypeError('credential cleanup observation is not absence or deletion');
    return actual;
  }
  if (!exactKeys(data, ['schemaVersion', 'kind', 'selector', 'stage', 'errorCode']) || data.schemaVersion !== 1 ||
      !['platform_load', 'delete_known', 'result_validation'].includes(data.stage as string) ||
      !['platform_store_unavailable', 'delete_denied', 'delete_failed'].includes(data.errorCode as string))
    throw new TypeError('credential cleanup failure projection is invalid');
  return immutableSnapshot({ ...data, selector: decodeSecretServiceSelector(data.selector) } as CredentialCleanupFailure);
}
/** Leaf reader: no history traversal, so terminal history can validate its
 * original revoke receipt without a history→receipt→history cycle. */
function readCredentialRevokeRow(held: CredentialBinding, requestId: string): CredentialRevokeRow | undefined {
  if (credentialSchemaVersion(held.database!) === 1) return undefined;
  const row = held.database!.prepare(`SELECT operation_json,cleanup_observation_json FROM credential_revoke_operations
    WHERE owner_principal_id=? AND request_id=?`).get(held.ownerPrincipalId, requestId);
  if (!row) return undefined;
  const operation = endpointJson(row.operation_json, decodeCredentialAuthorityRevokeOperation);
  if (operation.ownerPrincipalId !== held.ownerPrincipalId || operation.requestId !== requestId)
    throw new TypeError('credential revoke row identity differs');
  retainedCredentialChannel(held, operation);
  if (operation.cleanupPhase === 'metadata_committed') {
    if (row.cleanup_observation_json !== null) throw new TypeError('credential cleanup evidence precedes its phase');
    return { operation };
  }
  const observation = endpointJson(row.cleanup_observation_json, decodeCredentialCleanupObservation);
  if (canonicalJsonBytes(observation).length > 65536 || canonicalSha256(observation) !== operation.cleanupEvidenceDigest ||
      parseCanonicalTime(operation.cleanupFinishedAt) < parseCanonicalTime(operation.metadataCommittedAt) ||
      observation.selector.ownerPrincipalId !== held.ownerPrincipalId || observation.selector.stateRootIdentityDigest !== held.rootIdentity.identityDigest ||
      observation.selector.credentialGrantId !== operation.credentialGrantId ||
      (operation.cleanupPhase === 'cleanup_failed' ? observation.kind !== 'cleanup_failure' || observation.errorCode !== operation.cleanupErrorCode
        : observation.kind === 'cleanup_failure' || observation.bus.uid !== held.rootIdentity.ownerUid))
    throw new TypeError('credential cleanup receipt differs from its observation');
  return { operation, observation };
}
function validateCredentialRevokeResult(held: CredentialBinding, row: CredentialRevokeRow,
  record: CredentialAuthorityRecordV1, creating: CredentialAuthorityOperationV1): void {
  const operation = row.operation, core = operation.commandCore;
  if (record.state !== 'revoked' || operation.credentialGrantId !== record.credentialGrantId ||
      operation.committedAuthorityRevision !== record.authorityRevision || operation.revokedRecordDigest !== record.recordDigest ||
      core.credentialTargetDigest !== creating.credentialTargetDigest ||
      !canonicalJsonBytes(operation.platformItem).equals(canonicalJsonBytes(record.platformItem)) ||
      parseCanonicalTime(operation.metadataCommittedAt) < parseCanonicalTime(record.createdAt) ||
      parseCanonicalTime(operation.metadataCommittedAt) < parseCanonicalTime(record.revokedAt) ||
      (operation.disposition === 'revoked' ? core.expectedAuthorityRevision !== record.authorityRevision - 1 ||
        operation.requestId !== record.revokedByRequestId || operation.requestDigest !== record.revokedByRequestDigest ||
        operation.metadataCommittedAt !== record.revokedAt : core.expectedAuthorityRevision !== record.authorityRevision) ||
      (row.observation && !canonicalJsonBytes(row.observation.selector).equals(canonicalJsonBytes(credentialSelector(held, creating)))))
    throw new TypeError('credential revoke receipt differs from its terminal result');
}
function readCredentialHistory(held: CredentialBinding, grantId: string, resultRevision?: number):
  { latest?: CredentialAuthorityRecordV1; result?: CredentialAuthorityRecordV1; creating?: CredentialAuthorityOperationV1 } {
  let latest: CredentialAuthorityRecordV1 | undefined, result: CredentialAuthorityRecordV1 | undefined;
  let creating: CredentialAuthorityOperationV1 | undefined;
  for (const row of iterateNodeSqliteStatement(held.database!.prepare(`SELECT authority_revision,record_json FROM credential_records
    WHERE owner_principal_id=? AND credential_grant_id=? ORDER BY authority_revision`), held.ownerPrincipalId, grantId)) {
    const record = endpointJson(row.record_json, decodeCredentialAuthorityRecord);
    if (record.ownerPrincipalId !== held.ownerPrincipalId || record.credentialGrantId !== grantId ||
        record.authorityRevision !== (latest?.authorityRevision ?? 0) + 1 || row.authority_revision !== record.authorityRevision ||
        latest?.state === 'revoked' || record.credentialServiceRevision !== 1 ||
        (latest && (record.credentialHandleIdentityDigest !== latest.credentialHandleIdentityDigest ||
          parseCanonicalTime(record.createdAt) < parseCanonicalTime(latest.createdAt))))
      throw new TypeError('credential authority history is not contiguous');
    if (record.state === 'active') {
      const operation = credentialCreatingOperation(held, record);
      if (record.secretGeneration !== (latest?.secretGeneration ?? 0) + 1 || operation.kind !== (latest ? 'rotate' : 'enroll') ||
          (record.expiresAt && parseCanonicalTime(record.expiresAt) <= parseCanonicalTime(record.createdAt)))
        throw new TypeError('credential result kind, generation or expiry differs');
      creating = operation;
    } else {
      if (!latest || !creating) throw new TypeError('credential revoke has no active predecessor');
      const { recordDigest: _old, ...active } = latest, { recordDigest: _new, ...terminal } = record;
      if (!canonicalJsonBytes(terminal).equals(canonicalJsonBytes({ ...active, authorityRevision: latest.authorityRevision + 1,
        state: 'revoked', revokedAt: record.revokedAt, revokedByRequestId: record.revokedByRequestId,
        revokedByRequestDigest: record.revokedByRequestDigest }))) throw new TypeError('credential revoke rewrites its active predecessor');
      const row = readCredentialRevokeRow(held, record.revokedByRequestId);
      if (!row || row.operation.disposition !== 'revoked') throw new TypeError('credential revoke has no original receipt');
      validateCredentialRevokeResult(held, row, record, creating);
    }
    latest = record;
    if (record.authorityRevision === resultRevision) result = record;
  }
  if (!latest && (held.database!.prepare(`SELECT 1 FROM credential_operation_facts WHERE owner_principal_id=?
    AND credential_grant_id=? AND phase_rank=2 AND json_extract(operation_json,'$.phase')='committed' LIMIT 1`).get(held.ownerPrincipalId, grantId) ||
    held.database!.prepare(`SELECT 1 FROM credential_revoke_operations WHERE owner_principal_id=?
      AND json_extract(operation_json,'$.credentialGrantId')=? LIMIT 1`).get(held.ownerPrincipalId, grantId)))
    throw new TypeError('credential committed operation has no authority result');
  return { latest, result, creating };
}
function readCredentialWriteOperation(held: CredentialBinding, request: CredentialWriteRequest): CredentialAuthorityOperationV1 | undefined {
  ensureEndpointSchema(held.database!);
  if (credentialSchemaVersion(held.database!) === 1) return undefined;
  if (held.database!.prepare('SELECT 1 FROM credential_revoke_operations WHERE owner_principal_id=? AND request_id=?').get(held.ownerPrincipalId, request.requestId))
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential request already belongs to revocation');
  const facts = readCredentialFacts(held, request.requestId), operation = facts.at(-1)?.operation;
  if (!operation) return undefined;
  const core = operation.commandCore, endpoint = credentialEndpoint(held, core);
  if (core.kind !== request.kind || core.credentialGrantId !== request.credentialGrantId || core.secretSubmissionId !== request.secretSubmissionId)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential request already names different intent');
  let expiresAt = request.expiresAt;
  if (request.kind === 'enroll') {
    if (core.purpose !== request.purpose || endpoint.endpointRegistrationId !== request.endpointRegistrationId)
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential request already names different intent');
  } else {
    if (request.expectedAuthorityRevision !== operation.intendedAuthorityRevision - 1)
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential request already names different intent');
    const original = readCredentialHistory(held, operation.credentialGrantId, request.expectedAuthorityRevision).result;
    if (!original || original.state !== 'active') throw new TypeError('credential rotation has no original active revision');
    expiresAt ??= original.expiresAt;
  }
  if (core.expiresAt !== expiresAt) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential request already names different intent');
  if (operation.phase === 'committed') {
    const history = readCredentialHistory(held, operation.credentialGrantId, operation.committedAuthorityRevision);
    if (!history.result) throw new TypeError('credential replay has no historical result');
  }
  return immutableSnapshot(operation);
}
function appendCredentialFact(held: CredentialBinding, operation: CredentialAuthorityOperationV1, observation?: SecretServiceObservation): void {
  const bytes = canonicalJsonBytes(operation);
  if (bytes.length > SMALL_BYTES || (observation && canonicalJsonBytes(observation).length > 65536)) throw new TypeError('credential fact exceeds byte bound');
  held.database!.prepare(`INSERT INTO credential_operation_facts
    (owner_principal_id,request_id,credential_grant_id,attempt,phase_rank,operation_json,platform_observation_json) VALUES (?,?,?,?,?,?,?)`)
    .run(held.ownerPrincipalId, operation.requestId, operation.credentialGrantId, operation.attempt,
      operation.phase === 'prepared' ? 0 : operation.phase === 'secret_stored' ? 1 : 2, bytes.toString('utf8'),
      observation ? canonicalJsonBytes(observation).toString('utf8') : null);
}
function retainCredentialObjects(held: CredentialBinding, extra: readonly [string, Buffer][] = []): void {
  for (const [ref, bytes] of [...held.objects, ...extra]) {
    if (sha256Bytes(bytes) !== ref) throw new TypeError('credential retained object does not rehash');
    const prior = held.database!.prepare('SELECT bytes FROM retained_objects WHERE artifact_ref=?').get(ref)?.bytes;
    if (prior !== undefined) {
      if (!(prior instanceof Uint8Array) || !Buffer.from(prior).equals(bytes)) throw new TypeError('credential retained object bytes differ');
    } else held.database!.prepare('INSERT INTO retained_objects(artifact_ref,bytes) VALUES (?,?)').run(ref, bytes);
  }
}
function commitCredentialWrite(held: CredentialBinding, operation: CredentialAuthorityOperationV1, now: string): CredentialAuthorityOperationV1 {
  const core = operation.commandCore;
  const handle = { ownerPrincipalId: held.ownerPrincipalId, credentialGrantId: core.credentialGrantId, credentialServiceRevision: 1,
    purpose: core.purpose, endpointRegistrationRef: core.endpointRegistrationRef, endpointIdentityDigest: core.endpointIdentityDigest,
    tlsPolicyDigest: core.tlsPolicyDigest };
  const body = { schemaVersion: 1 as const, ...handle, authorityRevision: operation.intendedAuthorityRevision,
    credentialHandleIdentityDigest: canonicalSha256(handle), secretGeneration: operation.intendedSecretGeneration,
    externalSubject: core.externalSubject, externalSubjectDigest: core.externalSubjectDigest, platformItem: operation.platformItem,
    createdAt: now, ...(core.expiresAt ? { expiresAt: core.expiresAt } : {}), state: 'active' as const };
  const record = decodeCredentialAuthorityRecord({ ...body, recordDigest: canonicalSha256(body) });
  const committed = credentialTransition(operation, 'committed', { committedAuthorityRevision: record.authorityRevision, finishedAt: now });
  endpointTransaction(held.database!, () => {
    held.database!.prepare(`INSERT INTO credential_records(owner_principal_id,credential_grant_id,authority_revision,record_json) VALUES (?,?,?,?)`)
      .run(held.ownerPrincipalId, record.credentialGrantId, record.authorityRevision, canonicalJsonBytes(record).toString('utf8'));
    appendCredentialFact(held, committed);
    const result = readCredentialHistory(held, record.credentialGrantId, record.authorityRevision).result;
    if (!result || result.recordDigest !== record.recordDigest) throw new TypeError('credential committed result readback differs');
    assertInstalledCredentialScope(held.physical);
  });
  return immutableSnapshot(committed);
}
/** Repeated before input and at preparation. No subject, phase or secret is
 * produced by this read, and a rotation never derives its target from argv. */
function credentialWriteIntent(held: CredentialBinding, request: CredentialWriteRequest) {
  const previous = credentialSchemaVersion(held.database!) === 1 ? undefined : readCredentialHistory(held, request.credentialGrantId).latest;
  if (request.kind === 'enroll' && previous) throw new KernelStorageError('REVISION_CONFLICT', 'credential id is already enrolled');
  if (request.kind === 'rotate' && (!previous || previous.state !== 'active' || previous.authorityRevision !== request.expectedAuthorityRevision))
    throw new KernelStorageError('REVISION_CONFLICT', 'credential rotation requires its expected current active revision');
  if (request.kind === 'rotate' && held.database!.prepare(`SELECT 1 FROM credential_operation_facts
    WHERE owner_principal_id=? AND credential_grant_id=? AND phase_rank=2
      AND json_extract(operation_json,'$.phase')='committed'
      AND json_extract(operation_json,'$.commandCore.secretSubmissionId')=? LIMIT 1`)
    .get(held.ownerPrincipalId, request.credentialGrantId, request.secretSubmissionId))
    throw new KernelStorageError('INVALID_REQUEST', 'credential rotation requires a fresh secret submission id');
  // Reserve the final safe authority revision for terminal revocation.
  if (previous && (previous.authorityRevision >= Number.MAX_SAFE_INTEGER - 1 || previous.secretGeneration >= Number.MAX_SAFE_INTEGER))
    throw new KernelStorageError('REVISION_CONFLICT', 'credential revision or generation is exhausted');
  const originalEndpoint = previous && credentialEndpoint(held, credentialCreatingOperation(held, previous).commandCore);
  const endpointId = request.kind === 'enroll' ? request.endpointRegistrationId : originalEndpoint!.endpointRegistrationId;
  const purpose = request.kind === 'enroll' ? request.purpose : previous!.purpose;
  const endpoint = readEndpointHistory(held, endpointId).at(-1);
  if (!endpoint || endpoint.state !== 'active' || !endpoint.registration.purposes.includes(purpose) ||
      (previous && (endpoint.expectedRegistrationArtifactRef !== previous.endpointRegistrationRef ||
        endpoint.registration.endpointIdentityDigest !== previous.endpointIdentityDigest || endpoint.registration.tlsPolicyDigest !== previous.tlsPolicyDigest)))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential requires a current active endpoint of its purpose');
  const pending = credentialSchemaVersion(held.database!) !== 1 && held.database!.prepare(`SELECT 1 FROM credential_operation_facts AS f WHERE owner_principal_id=?
    AND credential_grant_id=? AND request_id<>? AND phase_rank=0 AND NOT EXISTS(SELECT 1 FROM credential_operation_facts AS t
      WHERE t.owner_principal_id=f.owner_principal_id AND t.request_id=f.request_id AND t.attempt=f.attempt AND t.phase_rank=2) LIMIT 1`)
    .get(held.ownerPrincipalId, request.credentialGrantId, request.requestId);
  if (pending) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential has a pending producer');
  return { previous, endpoint, purpose, expiresAt: request.expiresAt ?? (request.kind === 'rotate' ? previous!.expiresAt : undefined) };
}

function credentialWriteAttempts(held: CredentialBinding, requestId: string): CredentialAuthorityOperationV1[] {
  const facts = readCredentialFacts(held, requestId);
  return facts.filter((fact, index) => fact.operation.attempt !== facts[index + 1]?.operation.attempt).map(fact => fact.operation);
}
function assertCredentialPendingDead(held: CredentialBinding, attempts: readonly CredentialAuthorityOperationV1[]): void {
  for (const operation of attempts) {
    if (operation.phase !== 'prepared' && operation.phase !== 'secret_stored') continue;
    const original = retainedCredentialChannel(held, operation);
    let observed: 'present' | 'dead';
    try { observed = observeInstalledCredentialProducer(held.physical, original.processIdentity); }
    catch (error) {
      if (error instanceof ResourceRetirementError) throw error;
      throw new KernelStorageError('RECOVERY_REQUIRED', 'credential pending producer lifetime is unknown', { cause: error });
    }
    if (observed !== 'dead') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential pending producer is still present');
  }
}
function credentialFrozenWriteIntent(operation: CredentialAuthorityOperationV1,
  intent: ReturnType<typeof credentialWriteIntent>): void {
  const core = operation.commandCore;
  if (operation.intendedAuthorityRevision !== (intent.previous?.authorityRevision ?? 0) + 1 ||
      operation.intendedSecretGeneration !== (intent.previous?.secretGeneration ?? 0) + 1 ||
      core.purpose !== intent.purpose || core.endpointRegistrationRef !== intent.endpoint.expectedRegistrationArtifactRef ||
      core.endpointIdentityDigest !== intent.endpoint.registration.endpointIdentityDigest ||
      core.tlsPolicyDigest !== intent.endpoint.registration.tlsPolicyDigest || core.expiresAt !== intent.expiresAt)
    throw new KernelStorageError('REVISION_CONFLICT', 'credential frozen request no longer names its intended revision or generation');
}
/** Classification never writes a phase or touches the platform. A terminal
 * third abort refuses before input, service readiness or platform loading. */
function credentialWriteContinuation(held: CredentialBinding, request: CredentialWriteRequest): CredentialAuthorityOperationV1 | undefined {
  const operation = readCredentialWriteOperation(held, request);
  if (operation?.phase === 'committed') return operation;
  if (operation?.phase === 'aborted' && operation.attempt === 3)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential request exhausted its three attempts; a new request id is required');
  const intent = credentialWriteIntent(held, request);
  if (operation) {
    credentialFrozenWriteIntent(operation, intent);
    assertCredentialPendingDead(held, credentialWriteAttempts(held, request.requestId));
  }
  return operation;
}
function credentialWriteCleanupState(held: CredentialBinding, requestId: string) {
  const attempts = credentialWriteAttempts(held, requestId), operation = attempts.at(-1);
  if (!operation) throw new KernelStorageError('NOT_FOUND', 'credential cleanup request has no retained operation');
  const history = readCredentialHistory(held, operation.credentialGrantId,
    operation.phase === 'committed' ? operation.committedAuthorityRevision : undefined);
  if (operation.phase === 'committed' && !history.result) throw new TypeError('credential cleanup committed result is absent');
  assertCredentialPendingDead(held, attempts);
  const items = attempts.filter(candidate => !(history.latest?.state === 'active' &&
    canonicalJsonBytes(history.latest.platformItem).equals(canonicalJsonBytes(candidate.platformItem))));
  if ((operation.phase === 'prepared' || operation.phase === 'secret_stored') && !items.includes(operation))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'credential pending item is protected by current active authority');
  if (!items.length) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential cleanup cannot delete a current active item');
  return { operation, items };
}
/** Every sweep revisits the retained planned items, even terminal aborts.
 * Positive absence is this cut only; it cannot hide a later remote create. */
async function cleanupCredentialWriteRequest(held: CredentialBinding, requestId: string,
  platform: NativeCredentialPlatformBinding): Promise<CredentialAuthorityOperationV1> {
  const { operation, items } = credentialWriteCleanupState(held, requestId);
  for (const candidate of items) {
    const selector = credentialSelector(held, candidate);
    try {
      const observed = decodeSecretServiceObservation(await platform.secretService({ kind: 'delete_known', selector }));
      if (!['deleted', 'absent'].includes(observed.kind) || observed.bus.uid !== held.rootIdentity.ownerUid ||
          !canonicalJsonBytes(observed.selector).equals(canonicalJsonBytes(selector))) throw new TypeError('credential orphan deletion observation differs');
      assertInstalledCredentialScope(held.physical);
    } catch (error) {
      if (error instanceof ResourceRetirementError) throw error;
      throw new KernelStorageError('RECOVERY_REQUIRED', 'credential known-item cleanup did not prove absence or deletion', { cause: error });
    }
  }
  if (operation.phase !== 'prepared' && operation.phase !== 'secret_stored') return immutableSnapshot(operation);
  const finishedAt = encodeCanonicalTime(Math.max(Date.now(), parseCanonicalTime(operation.createdAt),
    parseCanonicalTime(held.channelIdentity.openedAt)));
  const aborted = credentialTransition(operation, 'aborted', { abortReason: 'recovered_orphan', finishedAt });
  endpointTransaction(held.database!, () => {
    appendCredentialFact(held, aborted);
    const result = readCredentialFacts(held, requestId).at(-1)?.operation;
    if (!result || !canonicalJsonBytes(result).equals(canonicalJsonBytes(aborted))) throw new TypeError('credential orphan abort readback differs');
    assertInstalledCredentialScope(held.physical);
  });
  return immutableSnapshot(aborted);
}

function prepareCredentialWrite(held: CredentialBinding, request: CredentialWriteRequest, secret: Buffer): CredentialAuthorityOperationV1 {
  ensureCredentialSchema(held.database!);
  const prior = readCredentialWriteOperation(held, request);
  if (prior && (prior.phase !== 'aborted' || prior.attempt === 3))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential preparation requires a fresh request or recoverable terminal abort');
  const intent = credentialWriteIntent(held, request), { previous, endpoint, purpose, expiresAt } = intent;
  if (prior) credentialFrozenWriteIntent(prior, intent);
  if (purpose === 'model_endpoint' && secret.some(byte => byte < 0x21 || byte > 0x7e))
    throw new KernelStorageError('INVALID_REQUEST', 'model credential secret is outside the installed bearer byte range');
  if (purpose === 'model_endpoint' && secret.length > 0 &&
      ['{', '}', '[', ']', '"', ':', 'application/json'].some(literal => Buffer.from(literal, 'ascii').includes(secret)))
    throw new KernelStorageError('INVALID_REQUEST', 'model credential secret conflicts with the installed protocol');
  const now = sampleCanonicalNow();
  if ([endpoint.createdAt, held.channelIdentity.openedAt, ...(previous ? [previous.createdAt] : []),
    ...(prior ? [prior.finishedAt!, prior.commandCore.externalSubject.observedAt] : [])].some(time => parseCanonicalTime(time) > parseCanonicalTime(now)) ||
      (expiresAt && parseCanonicalTime(expiresAt) <= parseCanonicalTime(now)))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential preparation time or expiry is invalid');
  const core = prior?.commandCore ?? (() => {
    const subjectBody = { schemaVersion: 1 as const, format: 'cliq-credential-external-subject-v1' as const,
      endpointIdentityDigest: endpoint.registration.endpointIdentityDigest,
      subject: { kind: 'opaque_generation' as const, opaqueSubjectId: randomBytes(32).toString('base64url'),
        scopes: ['endpoint_exact_only'] as ['endpoint_exact_only'], audiences: [] as [] }, observedAt: now };
    const externalSubject = { ...subjectBody, subjectDigest: canonicalSha256(subjectBody) };
    const target = { credentialGrantId: request.credentialGrantId, ownerPrincipalId: held.ownerPrincipalId, purpose,
      endpointRegistrationRef: endpoint.expectedRegistrationArtifactRef, endpointIdentityDigest: endpoint.registration.endpointIdentityDigest,
      tlsPolicyDigest: endpoint.registration.tlsPolicyDigest, ...(expiresAt ? { expiresAt } : {}),
      externalSubjectDigest: externalSubject.subjectDigest };
    const coreBody = { schemaVersion: 1 as const, ...target, kind: request.kind, secretSubmissionId: request.secretSubmissionId,
      externalSubject, credentialTargetDigest: canonicalSha256(target) };
    return decodeCredentialAuthorityCommandCore({ ...coreBody, commandDigest: canonicalSha256(coreBody) });
  })();
  const attempt = (prior?.attempt ?? 0) + 1 as 1 | 2 | 3;
  const operationBody = { schemaVersion: 1 as const, operationId: identityHash(held.ownerPrincipalId, request.requestId, core.commandDigest, attempt),
    requestId: request.requestId, requestDigest: core.commandDigest, channelIdentityRef: canonicalSha256(held.channelIdentity),
    channelIdentityDigest: held.channelIdentity.channelIdentityDigest, commandCore: core, attempt, ownerPrincipalId: held.ownerPrincipalId,
    kind: core.kind, credentialGrantId: core.credentialGrantId, credentialTargetDigest: core.credentialTargetDigest,
    intendedAuthorityRevision: (previous?.authorityRevision ?? 0) + 1, intendedSecretGeneration: (previous?.secretGeneration ?? 0) + 1,
    intendedExternalSubjectDigest: core.externalSubjectDigest,
    platformItem: { kind: 'linux_secret_service' as const, schema: 'org.freedesktop.Secret.Generic' as const,
      collection: 'default' as const, itemId: identityHash('cliq-credential-platform-item-v1', randomBytes(32).toString('base64url')) },
    createdAt: now, phase: 'prepared' as const };
  const operation = decodeCredentialAuthorityOperation({ ...operationBody, operationDigest: canonicalSha256(operationBody) });
  endpointTransaction(held.database!, () => {
    retainCredentialObjects(held, [[core.endpointRegistrationRef, canonicalJsonBytes(endpoint.registration)]]);
    appendCredentialFact(held, operation); readCredentialFacts(held, request.requestId);
    assertInstalledCredentialScope(held.physical);
  });
  return operation;
}
function credentialTransition(operation: CredentialAuthorityOperationV1, phase: 'secret_stored' | 'committed' | 'aborted',
  fields: { committedAuthorityRevision?: number; abortReason?: 'platform_store_failed' | 'recovered_orphan'; finishedAt?: string } = {}): CredentialAuthorityOperationV1 {
  const { operationDigest: _digest, ...original } = operation;
  const body = { ...original, phase, ...fields };
  return decodeCredentialAuthorityOperation({ ...body, operationDigest: canonicalSha256(body) });
}
async function readCredentialSecret(): Promise<Buffer> {
  if (process.stdin.isTTY) throw new KernelStorageError('INVALID_REQUEST', 'credential integration requires a non-echoing fd-0 input channel');
  const chunks: Buffer[] = []; let count = 0;
  const timer = setTimeout(() => process.stdin.destroy(new Error('credential secret input timed out')), 10000);
  try {
    for await (const chunk of process.stdin) {
      const bytes = Buffer.from(chunk); chunks.push(bytes); count += bytes.length;
      if (count > 65536) throw new TypeError('credential secret exceeds input bound');
    }
    if (!count) throw new TypeError('credential secret is empty');
    return Buffer.concat(chunks);
  } catch { throw new KernelStorageError('INVALID_REQUEST', 'credential secret input is unavailable or outside its byte bound'); }
  finally { clearTimeout(timer); for (const bytes of chunks) bytes.fill(0); }
}
/** Complete fixed installed business action. Input and phase writers are owned
 * here, not exposed as injectable callbacks/factories or public phase methods. */
export async function writeCredentialAuthority(selected: HeldInstalledRuntime, request: CredentialWriteRequest): Promise<CredentialAuthorityOperationV1> {
  noteInstalledCredentialPhase('history');
  const initial = await withCredentialAuthorityLock(selected, async token => {
    const held = checkedCredentialToken(token); request = decodeCredentialWriteRequest(request);
    return credentialWriteContinuation(held, request);
  });
  if (initial?.phase === 'committed') return initial;
  let platform: NativeCredentialPlatformBinding | undefined;
  if (initial) {
    // Loading is outside the retired scope; private locked helpers never
    // reacquire a lock or call back into the selected runtime's loader.
    platform = await loadInstalledCredentialPlatform(selected);
    const resumed = await withCredentialAuthorityLock(selected, async token => {
      const held = checkedCredentialToken(token), current = credentialWriteContinuation(held, request);
      if (current?.phase === 'committed') return current;
      if (!current) throw new TypeError('credential retry lost its retained operation');
      await cleanupCredentialWriteRequest(held, request.requestId, platform!);
      return credentialWriteContinuation(held, request);
    });
    if (resumed?.phase === 'committed') return resumed;
  }
  noteInstalledCredentialPhase('first_supervisor');
  let client = await ensureInstalledCredentialSupervisor(selected);
  let secret: Buffer | undefined;
  try {
    noteInstalledCredentialPhase('secret_input');
    secret = await readCredentialSecret();
    // Input waited without credential locks. Freshly authenticate the same
    // current owner before preparation instead of reusing old readiness.
    noteInstalledCredentialPhase('second_supervisor');
    await client.reobserve();
    noteInstalledCredentialPhase('platform_store');
    platform ??= await loadInstalledCredentialPlatform(selected);
    const operation = await withCredentialAuthorityLock(selected, async token => {
      const held = checkedCredentialToken(token), raced = credentialWriteContinuation(held, request);
      if (raced?.phase === 'committed') return raced;
      // The input interval was unlocked. Re-sweep every retained abandoned
      // item, and only then create the next contiguous frozen-core attempt.
      if (raced) {
        await cleanupCredentialWriteRequest(held, request.requestId, platform!);
        credentialWriteContinuation(held, request);
      }
      const prepared = prepareCredentialWrite(held, request, secret!);
      let observation: SecretServiceObservation;
      try {
        observation = decodeSecretServiceObservation(await platform!.secretService({ kind: 'create_compare',
          selector: credentialSelector(held, prepared), secret: secret! }));
        if (observation.kind !== 'stored' || observation.bus.uid !== held.rootIdentity.ownerUid ||
            !canonicalJsonBytes(observation.selector).equals(canonicalJsonBytes(credentialSelector(held, prepared))))
          throw new TypeError('actual credential store result differs');
        token.assertHeld();
      } catch (error) {
        if (error instanceof ResourceRetirementError) throw error;
        const finishedAt = encodeCanonicalTime(Math.max(Date.now(), parseCanonicalTime(prepared.createdAt)));
        const aborted = credentialTransition(prepared, 'aborted', { abortReason: 'platform_store_failed', finishedAt });
        endpointTransaction(held.database!, () => { appendCredentialFact(held, aborted); token.assertHeld(); });
        throw new KernelStorageError('RECOVERY_REQUIRED', 'credential store did not complete a fresh secret round-trip');
      } finally { secret!.fill(0); }
      const stored = credentialTransition(prepared, 'secret_stored');
      endpointTransaction(held.database!, () => { appendCredentialFact(held, stored, observation);
        readCredentialFacts(held, request.requestId); token.assertHeld(); });
      return stored;
    });
    if (operation.phase === 'committed') return operation;
    // This call starts only after both pager and native scope have retired.
    noteInstalledCredentialPhase('finalize');
    const committed = await client.finalize({ protocolVersion: 1, method: 'credential.finalize', requestId: operation.requestId,
      operationId: operation.operationId, attempt: operation.attempt, commandDigest: operation.requestDigest });
    if (committed.kind === 'rotate') {
      // Publication is authoritative before cleanup acquires another scope.
      // A failed delete cannot roll back or rewrite this committed result;
      // the retained creating operation keeps the old item sweepable.
      try {
        await withCredentialAuthorityLock(selected, async token => {
          const held = checkedCredentialToken(token), history = readCredentialHistory(held, committed.credentialGrantId,
            committed.intendedAuthorityRevision - 1), previous = history.result;
          if (!previous || previous.state !== 'active') throw new TypeError('rotation cleanup has no original active revision');
          if (history.latest?.state === 'active' && canonicalJsonBytes(history.latest.platformItem).equals(canonicalJsonBytes(previous.platformItem))) return;
          const selector = credentialSelector(held, credentialCreatingOperation(held, previous));
          const observed = decodeSecretServiceObservation(await platform!.secretService({ kind: 'delete_known', selector }));
          if (!['deleted', 'absent'].includes(observed.kind) || observed.bus.uid !== held.rootIdentity.ownerUid ||
              !canonicalJsonBytes(observed.selector).equals(canonicalJsonBytes(selector))) throw new TypeError('rotation cleanup observation differs');
          token.assertHeld();
        });
      } catch (error) { if (error instanceof ResourceRetirementError) throw error; }
    }
    return committed;
  } finally { secret?.fill(0); noteInstalledCredentialPhase('retire'); await client.close(); }
}

function commitCredentialRevocation(held: CredentialBinding, request: CredentialRevokeRequest): CredentialAuthorityRevokeOperationV1 {
  ensureEndpointSchema(held.database!);
  if (credentialSchemaVersion(held.database!) === 1) throw new KernelStorageError('NOT_FOUND', 'credential has no committed authority');
  if (readCredentialFacts(held, request.requestId).length)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential revoke request already belongs to a write');
  const prior = readCredentialRevokeRow(held, request.requestId);
  if (prior && (prior.operation.credentialGrantId !== request.credentialGrantId ||
      prior.operation.commandCore.expectedAuthorityRevision !== request.expectedAuthorityRevision))
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential revoke request already names different intent');
  const history = readCredentialHistory(held, request.credentialGrantId), latest = history.latest, creating = history.creating;
  if (!latest || !creating) throw new KernelStorageError('NOT_FOUND', 'credential has no committed authority');
  if (prior) { validateCredentialRevokeResult(held, prior, latest, creating); return immutableSnapshot(prior.operation); }
  if (latest.authorityRevision !== request.expectedAuthorityRevision || latest.state === 'active' && latest.authorityRevision >= Number.MAX_SAFE_INTEGER)
    throw new KernelStorageError('REVISION_CONFLICT', 'credential revoke requires its expected current revision');
  const coreBody = { schemaVersion: 1 as const, kind: 'revoke' as const, ownerPrincipalId: held.ownerPrincipalId,
    credentialGrantId: request.credentialGrantId, expectedAuthorityRevision: request.expectedAuthorityRevision,
    credentialTargetDigest: creating.credentialTargetDigest };
  const core = decodeCredentialAuthorityRevokeCommandCore({ ...coreBody, commandDigest: canonicalSha256(coreBody) });
  // Non-expanding causal audit only: revocation does not consult or heal the
  // Run time fence, and a wall-clock regression must not restore permission.
  const now = encodeCanonicalTime(Math.max(Date.now(), parseCanonicalTime(held.channelIdentity.openedAt),
    parseCanonicalTime(latest.state === 'revoked' ? latest.revokedAt : latest.createdAt)));
  const record = latest.state === 'revoked' ? latest : (() => {
    const { recordDigest: _digest, ...active } = latest;
    const body = { ...active, authorityRevision: latest.authorityRevision + 1, state: 'revoked' as const,
      revokedAt: now, revokedByRequestId: request.requestId, revokedByRequestDigest: core.commandDigest };
    return decodeCredentialAuthorityRecord({ ...body, recordDigest: canonicalSha256(body) });
  })();
  const body = { schemaVersion: 1 as const, operationId: identityHash(held.ownerPrincipalId, request.requestId, core.commandDigest),
    requestId: request.requestId, requestDigest: core.commandDigest, channelIdentityRef: canonicalSha256(held.channelIdentity),
    channelIdentityDigest: held.channelIdentity.channelIdentityDigest, commandCore: core, ownerPrincipalId: held.ownerPrincipalId,
    credentialGrantId: record.credentialGrantId, credentialTargetDigest: core.credentialTargetDigest,
    disposition: latest.state === 'revoked' ? 'already_revoked' as const : 'revoked' as const,
    committedAuthorityRevision: record.authorityRevision, revokedRecordDigest: record.recordDigest, platformItem: record.platformItem,
    metadataCommittedAt: now, cleanupPhase: 'metadata_committed' as const };
  const operation = decodeCredentialAuthorityRevokeOperation({ ...body, operationDigest: canonicalSha256(body) });
  endpointTransaction(held.database!, () => {
    retainCredentialObjects(held);
    if (latest.state === 'active') held.database!.prepare(`INSERT INTO credential_records
      (owner_principal_id,credential_grant_id,authority_revision,record_json) VALUES (?,?,?,?)`)
      .run(held.ownerPrincipalId, record.credentialGrantId, record.authorityRevision, canonicalJsonBytes(record).toString('utf8'));
    held.database!.prepare(`INSERT INTO credential_revoke_operations(owner_principal_id,request_id,operation_json,cleanup_observation_json)
      VALUES (?,?,?,NULL)`).run(held.ownerPrincipalId, request.requestId, canonicalJsonBytes(operation).toString('utf8'));
    const checked = readCredentialHistory(held, record.credentialGrantId), row = readCredentialRevokeRow(held, request.requestId);
    if (!row || !checked.latest || !checked.creating) throw new TypeError('credential revoke readback is absent');
    validateCredentialRevokeResult(held, row, checked.latest, checked.creating); assertInstalledCredentialScope(held.physical);
  });
  return immutableSnapshot(operation);
}

/** Terminal metadata commits before any GIO load or platform operation. */
export async function revokeCredentialAuthority(selected: HeldInstalledRuntime, request: CredentialRevokeRequest): Promise<CredentialAuthorityRevokeOperationV1> {
  const committed = await withCredentialAuthorityLock(selected, async token => {
    const held = checkedCredentialToken(token); request = decodeCredentialRevokeRequest(request);
    return commitCredentialRevocation(held, request);
  });
  if (committed.cleanupPhase === 'cleanup_complete') return committed;
  return cleanupCredentialRevocation(selected, request.requestId, false);
}

/** This owning phase names the retained receipt, never manufactures another
 * revoke command or calls an auto-locking action from inside its scope. */
async function cleanupCredentialRevocation(selected: HeldInstalledRuntime, requestId: string,
  explicit: boolean): Promise<CredentialAuthorityRevokeOperationV1> {
  let platform: NativeCredentialPlatformBinding | undefined, loadFailed = false;
  try { platform = await loadInstalledCredentialPlatform(selected); }
  catch (error) { if (error instanceof ResourceRetirementError) throw error; loadFailed = true; }
  return withCredentialAuthorityLock(selected, async token => {
    const held = checkedCredentialToken(token), row = readCredentialRevokeRow(held, requestId);
    if (!row) throw new TypeError('credential revoke cleanup lost its original receipt');
    const history = readCredentialHistory(held, row.operation.credentialGrantId);
    if (!history.latest || !history.creating) throw new TypeError('credential revoke cleanup has no terminal result');
    validateCredentialRevokeResult(held, row, history.latest, history.creating);
    if (row.operation.cleanupPhase === 'cleanup_complete' && !explicit) return immutableSnapshot(row.operation);
    const selector = credentialSelector(held, history.creating);
    let observation: CredentialCleanupObservation;
    if (loadFailed) observation = { schemaVersion: 1, kind: 'cleanup_failure', selector,
      stage: 'platform_load', errorCode: 'platform_store_unavailable' };
    else {
      let stage: CredentialCleanupFailure['stage'] = 'delete_known';
      try {
        const value = await platform!.secretService({ kind: 'delete_known', selector }); stage = 'result_validation';
        const actual = decodeSecretServiceObservation(value);
        if (!['deleted', 'absent'].includes(actual.kind) || actual.bus.uid !== held.rootIdentity.ownerUid ||
            !canonicalJsonBytes(actual.selector).equals(canonicalJsonBytes(selector))) throw new TypeError('credential revoke deletion observation differs');
        observation = actual;
      } catch (error) {
        if (error instanceof ResourceRetirementError) throw error;
        const code = (error as { cause?: { platformCode?: unknown } } | null)?.cause?.platformCode;
        observation = { schemaVersion: 1, kind: 'cleanup_failure', selector, stage,
          errorCode: stage === 'result_validation' ? 'delete_failed' : code === 'delete_denied' || code === 'delete_failed' ? code : 'platform_store_unavailable' };
      }
    }
    token.assertHeld();
    const original = row.operation;
    // Completed receipts are historical results. Explicit cleanup repeats the
    // actual known-item sweep, but neither success nor failure rewrites them.
    if (original.cleanupPhase === 'cleanup_complete') {
      if (observation.kind === 'cleanup_failure')
        throw new KernelStorageError('RECOVERY_REQUIRED', 'credential completed receipt fresh sweep did not prove absence or deletion');
      return immutableSnapshot(original);
    }
    const { operationDigest: _digest, cleanupPhase: _phase, cleanupEvidenceDigest: _evidence,
      cleanupErrorCode: _error, cleanupFinishedAt: _finished, ...identity } = original;
    const finishedAt = encodeCanonicalTime(Math.max(Date.now(), parseCanonicalTime(held.channelIdentity.openedAt),
      parseCanonicalTime(original.metadataCommittedAt), ...(_finished ? [parseCanonicalTime(_finished)] : [])));
    const body = { ...identity, cleanupEvidenceDigest: canonicalSha256(observation), cleanupFinishedAt: finishedAt,
      ...(observation.kind === 'cleanup_failure' ? { cleanupPhase: 'cleanup_failed' as const, cleanupErrorCode: observation.errorCode }
        : { cleanupPhase: 'cleanup_complete' as const }) };
    const operation = decodeCredentialAuthorityRevokeOperation({ ...body, operationDigest: canonicalSha256(body) });
    if (canonicalJsonBytes(observation).length > 65536) throw new TypeError('credential cleanup observation exceeds byte bound');
    endpointTransaction(held.database!, () => {
      held.database!.prepare(`UPDATE credential_revoke_operations SET operation_json=?,cleanup_observation_json=?
        WHERE owner_principal_id=? AND request_id=?`).run(canonicalJsonBytes(operation).toString('utf8'),
          canonicalJsonBytes(observation).toString('utf8'), held.ownerPrincipalId, requestId);
      const checked = readCredentialRevokeRow(held, requestId);
      if (!checked || !canonicalJsonBytes(checked.operation).equals(canonicalJsonBytes(operation))) throw new TypeError('credential cleanup readback differs');
      validateCredentialRevokeResult(held, checked, history.latest!, history.creating!); token.assertHeld();
    });
    return immutableSnapshot(operation);
  });
}

function credentialCleanupKind(held: CredentialBinding, requestId: string): 'write' | 'revoke' {
  ensureEndpointSchema(held.database!);
  const facts = readCredentialFacts(held, requestId), row = readCredentialRevokeRow(held, requestId);
  if (facts.length && row) throw new TypeError('credential cleanup request belongs to more than one action');
  if (row) {
    const history = readCredentialHistory(held, row.operation.credentialGrantId);
    if (!history.latest || !history.creating) throw new TypeError('credential cleanup revoke result is absent');
    validateCredentialRevokeResult(held, row, history.latest, history.creating);
    return 'revoke';
  }
  if (facts.length) { credentialWriteCleanupState(held, requestId); return 'write'; }
  throw new KernelStorageError('NOT_FOUND', 'credential cleanup request has no retained operation');
}

/** Explicit cleanup is independent of input and Supervisor availability.
 * Only the selected producer owns the platform; no scope/phase factory leaks. */
export async function cleanupCredentialAuthority(selected: HeldInstalledRuntime, request: CredentialCleanupRequest):
Promise<CredentialAuthorityOperationV1 | CredentialAuthorityRevokeOperationV1> {
  const kind = await withCredentialAuthorityLock(selected, async token => {
    request = decodeCredentialCleanupRequest(request);
    return credentialCleanupKind(checkedCredentialToken(token), request.requestId);
  });
  if (kind === 'revoke') return cleanupCredentialRevocation(selected, request.requestId, true);
  let platform: NativeCredentialPlatformBinding;
  try { platform = await loadInstalledCredentialPlatform(selected); }
  catch (error) {
    if (error instanceof ResourceRetirementError) throw error;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'credential known-item cleanup platform is unavailable', { cause: error });
  }
  return withCredentialAuthorityLock(selected, async token => {
    const held = checkedCredentialToken(token);
    if (credentialCleanupKind(held, request.requestId) !== kind) throw new TypeError('credential cleanup action changed');
    return cleanupCredentialWriteRequest(held, request.requestId, platform);
  });
}

/** Locked same-principal lookup. A caller id never selects a different owner;
 * neither SQL nor the physical store lifetime escapes the installed producer. */
export function readEndpointAuthority(token: HeldCredentialAuthorityLock, endpointRegistrationId: string): EndpointAuthorityRecordV1 | null {
  const held = checkedCredentialToken(token);
  try {
    if (typeof endpointRegistrationId !== 'string' || !endpointRegistrationId ||
        normalizeCanonicalText(endpointRegistrationId) !== endpointRegistrationId || Buffer.byteLength(endpointRegistrationId) > SMALL_BYTES)
      throw new TypeError('invalid endpoint id');
  } catch (cause) { throw new KernelStorageError('INVALID_REQUEST', 'endpoint id must be bounded nonempty canonical text', { cause }); }
  try {
    ensureEndpointSchema(held.database!);
    const history = readEndpointHistory(held, endpointRegistrationId);
    assertInstalledCredentialScope(held.physical);
    return history.length ? immutableSnapshot(history[history.length - 1]!) : null;
  } catch (cause) {
    if (cause instanceof ResourceRetirementError) throw cause;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained endpoint authority could not be verified', { cause });
  }
}

/** Authenticated exact-core mutation. Current identity always precedes replay;
 * the first operation's channel and historical result are never rewritten. */
export function commitEndpointAuthority(token: HeldCredentialAuthorityLock, requestId: string,
  commandCore: EndpointAuthorityCommandCoreV1): EndpointAuthorityOperationV1 {
  const held = checkedCredentialToken(token);
  let core: EndpointAuthorityCommandCoreV1;
  let coreBytes: Buffer;
  try {
    if (typeof requestId !== 'string') throw new TypeError('invalid endpoint request id');
    assertRequestId(requestId);
    coreBytes = canonicalJsonBytes(commandCore);
    if (coreBytes.length > SMALL_BYTES) throw new TypeError('endpoint command exceeds its byte bound');
    core = immutableSnapshot(decodeEndpointAuthorityCommandCore(parseJsonStrict(coreBytes.toString('utf8'))));
    if (core.ownerPrincipalId !== held.ownerPrincipalId) throw new TypeError('endpoint owner differs from authenticated principal');
  } catch (cause) { throw new KernelStorageError('INVALID_REQUEST', 'endpoint command is invalid for this authenticated principal', { cause }); }
  try {
    const database = held.database!;
    ensureEndpointSchema(database);
    const endpointId = core.kind === 'register' ? core.registration.endpointRegistrationId : core.endpointRegistrationId;
    const previous = readEndpointOperation(held, requestId);
    if (previous) {
      const history = readEndpointHistory(held, previous.endpointRegistrationId);
      validateEndpointResult(previous, history);
      if (previous.requestDigest !== core.commandDigest || !canonicalJsonBytes(previous.commandCore).equals(coreBytes))
        throw new KernelStorageError('REQUEST_ID_CONFLICT', 'endpoint request id already names different command bytes');
      return immutableSnapshot(previous);
    }
    const history = readEndpointHistory(held, endpointId);
    const latest = history[history.length - 1];
    const now = encodeCanonicalTime(Date.now());
    if (parseCanonicalTime(now) < parseCanonicalTime(held.lastCommittedAt ?? held.channelIdentity.openedAt) ||
        (latest && parseCanonicalTime(now) < parseCanonicalTime(latest.state === 'revoked' ? latest.revokedAt : latest.createdAt)))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint authority wall clock regressed');
    let record: EndpointAuthorityRecordV1;
    let disposition: EndpointAuthorityOperationV1['disposition'];
    if (core.kind === 'register') {
      verifyEndpointTrust(held, core.registration, false);
      if (core.registration.registrationKind !== 'user' || parseCanonicalTime(core.registration.createdAt) > parseCanonicalTime(now))
        throw new KernelStorageError('INVALID_REQUEST', 'endpoint registration must be an already-created user registration');
      if (latest?.state === 'revoked') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'a revoked endpoint id cannot be registered again');
      if (latest) {
        if (latest.expectedRegistrationArtifactRef !== core.expectedRegistrationArtifactRef ||
            !canonicalJsonBytes(latest.registration).equals(canonicalJsonBytes(core.registration)))
          throw new KernelStorageError('REVISION_CONFLICT', 'endpoint id already names a different registration');
        record = latest; disposition = 'already_registered';
      } else {
        const value = { schemaVersion: 1, endpointRegistrationId: endpointId, authorityRevision: 1, ownerPrincipalId: held.ownerPrincipalId,
          sourceRequestId: requestId, sourceRequestDigest: core.commandDigest, registration: core.registration,
          expectedRegistrationArtifactRef: core.expectedRegistrationArtifactRef, createdAt: now, state: 'active' } as const;
        record = decodeEndpointAuthorityRecord({ ...value, recordDigest: canonicalSha256(value) }); disposition = 'registered';
      }
    } else {
      if (!latest) throw new KernelStorageError('NOT_FOUND', 'endpoint id is not registered');
      if (latest.state === 'revoked') { record = latest; disposition = 'already_revoked'; }
      else {
        if (core.expectedAuthorityRevision !== latest.authorityRevision)
          throw new KernelStorageError('REVISION_CONFLICT', 'endpoint active revision differs from the expected revision');
        const { recordDigest: _digest, ...original } = latest;
        const value = { ...original, authorityRevision: 2, state: 'revoked', revokedAt: now,
          revokedByRequestId: requestId, revokedByRequestDigest: core.commandDigest } as const;
        record = decodeEndpointAuthorityRecord({ ...value, recordDigest: canonicalSha256(value) }); disposition = 'revoked';
      }
    }
    const value = { schemaVersion: 1, operationId: identityHash(held.ownerPrincipalId, requestId, core.commandDigest),
      requestId, requestDigest: core.commandDigest, channelIdentityRef: canonicalSha256(held.channelIdentity),
      channelIdentityDigest: held.channelIdentity.channelIdentityDigest, commandCore: core, ownerPrincipalId: held.ownerPrincipalId,
      kind: core.kind, endpointRegistrationId: endpointId, disposition, committedAuthorityRevision: record.authorityRevision,
      resultRecordDigest: record.recordDigest, committedAt: now } as const;
    const operation = decodeEndpointAuthorityOperation({ ...value, operationDigest: canonicalSha256(value) });
    const recordBytes = canonicalJsonBytes(record), operationBytes = canonicalJsonBytes(operation);
    if (recordBytes.length > SMALL_BYTES || operationBytes.length > SMALL_BYTES)
      throw new KernelStorageError('INVALID_REQUEST', 'endpoint authority result exceeds its byte bound');
    endpointTransaction(database, () => {
      for (const [ref, bytes] of held.objects) {
        const existing = database.prepare('SELECT bytes FROM retained_objects WHERE artifact_ref=?').get(ref);
        if (existing) {
          if (!(existing.bytes instanceof Uint8Array) || !Buffer.from(existing.bytes).equals(bytes))
            throw new TypeError('retained endpoint object differs from its original bytes');
        } else database.prepare('INSERT INTO retained_objects(artifact_ref,bytes) VALUES (?,?)').run(ref, bytes);
      }
      if (disposition === 'registered' || disposition === 'revoked') database.prepare(`INSERT INTO endpoint_records
        (owner_principal_id,endpoint_registration_id,authority_revision,record_json) VALUES (?,?,?,?)`)
        .run(held.ownerPrincipalId, endpointId, record.authorityRevision, recordBytes.toString('utf8'));
      database.prepare('INSERT INTO endpoint_operations(owner_principal_id,request_id,operation_json) VALUES (?,?,?)')
        .run(held.ownerPrincipalId, requestId, operationBytes.toString('utf8'));
      validateEndpointResult(operation, readEndpointHistory(held, endpointId));
      assertInstalledCredentialScope(held.physical);
    });
    held.lastCommittedAt = now;
    return immutableSnapshot(operation);
  } catch (cause) {
    if (cause instanceof KernelStorageError) throw cause;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint authority transaction could not be verified', { cause });
  }
}

function endpointTransaction<T>(database: DatabaseSync, operation: () => T): T {
  database.exec('BEGIN IMMEDIATE');
  try { const result = operation(); database.exec('COMMIT'); return result; }
  catch (cause) {
    try { database.exec('ROLLBACK'); }
    catch (rollback) { throw new ResourceRetirementError('endpoint authority transaction retirement is uncertain', new AggregateError([cause, rollback])); }
    throw cause;
  }
}

function ensureEndpointSchema(database: DatabaseSync): void {
  const version = database.prepare('PRAGMA user_version').get()?.user_version;
  const names = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'").all().map(row => row.name).sort();
  if (version === 1 && JSON.stringify(names) === JSON.stringify(['endpoint_operations', 'endpoint_records', 'retained_objects'])) return;
  if (version === 2 && JSON.stringify(names) === JSON.stringify(['credential_operation_facts', 'credential_records', 'credential_revoke_operations',
    'endpoint_operations', 'endpoint_records', 'retained_objects'])) return;
  if (version !== 0 || names.length) throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint authority schema is not supported');
  // Schema genesis is harmless and replayable. A warm read establishes it
  // before the production business-transaction crash campaign starts.
  endpointTransaction(database, () => database.exec(`
    CREATE TABLE endpoint_records(owner_principal_id TEXT NOT NULL, endpoint_registration_id TEXT NOT NULL,
      authority_revision INTEGER NOT NULL CHECK(authority_revision IN (1,2)), record_json TEXT NOT NULL,
      PRIMARY KEY(owner_principal_id,endpoint_registration_id,authority_revision)) STRICT;
    CREATE TABLE endpoint_operations(owner_principal_id TEXT NOT NULL, request_id TEXT NOT NULL,
      operation_json TEXT NOT NULL, PRIMARY KEY(owner_principal_id,request_id)) STRICT;
    CREATE TABLE retained_objects(artifact_ref TEXT PRIMARY KEY NOT NULL, bytes BLOB NOT NULL) STRICT;
    PRAGMA user_version=1;
  `));
}

function endpointJson<T>(text: unknown, decode: (value: unknown) => T): T {
  if (typeof text !== 'string' || Buffer.byteLength(text) > SMALL_BYTES) throw new TypeError('endpoint JSON is not bounded text');
  const bytes = Buffer.from(text), value = parseJsonStrict(text);
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('endpoint JSON is not canonical');
  return decode(value);
}

function endpointObject(held: CredentialBinding, ref: string, limit = SMALL_BYTES, retained = true): Buffer {
  const value = retained ? held.database!.prepare('SELECT bytes FROM retained_objects WHERE artifact_ref=?').get(ref)?.bytes : held.objects.get(ref);
  if (!(value instanceof Uint8Array) || value.length > limit || sha256Bytes(value) !== ref)
    throw new TypeError('endpoint retained object is missing or does not rehash');
  return Buffer.from(value);
}

function verifyEndpointTrust(held: CredentialBinding, registration: EndpointRegistrationV1, retained: boolean): void {
  const tls = registration.tls;
  const selected = held.selected.bundle.entries.find(value => value.entryId === 'default_https_trust_store');
  if (tls.trustStoreRuntimeBundleRef !== held.selected.bundleDigest || tls.trustStoreRuntimeBundleManifestDigest !== held.selected.bundle.manifestDigest ||
      !selected || selected.role !== 'trust_store' || selected.executable || selected.digest !== tls.trustStoreRef || selected.digest !== tls.trustStoreDigest)
    throw new KernelStorageError(retained ? 'RECOVERY_REQUIRED' : 'INVALID_REQUEST', 'endpoint must use the fixed signed installed HTTPS trust store');
  const bundleBytes = endpointObject(held, tls.trustStoreRuntimeBundleRef, SMALL_BYTES, retained);
  const bundle = validateBundle(checkCanonicalBytes(bundleBytes), held.releaseKeys);
  const entry = bundle.entries.find(value => value.entryId === 'default_https_trust_store');
  if (tls.trustStoreRuntimeBundleRef !== held.selected.bundleDigest || bundle.manifestDigest !== tls.trustStoreRuntimeBundleManifestDigest ||
      !entry || entry.role !== 'trust_store' || entry.executable || entry.digest !== tls.trustStoreRef || entry.digest !== tls.trustStoreDigest)
    throw new KernelStorageError(retained ? 'RECOVERY_REQUIRED' : 'INVALID_REQUEST', 'endpoint must use the fixed signed installed HTTPS trust store');
  const bytes = endpointObject(held, entry.digest, TRUST_BYTES, retained);
  if (bytes.length !== entry.byteCount) throw new TypeError('endpoint trust-store byte count differs from the signed entry');
  validateTrustStore(bytes);
}

function readEndpointOperation(held: CredentialBinding, requestId: string): EndpointAuthorityOperationV1 | undefined {
  try {
    const row = held.database!.prepare('SELECT operation_json FROM endpoint_operations WHERE owner_principal_id=? AND request_id=?')
      .get(held.ownerPrincipalId, requestId);
    if (!row) return undefined;
    const operation = endpointJson(row.operation_json, decodeEndpointAuthorityOperation);
    if (operation.ownerPrincipalId !== held.ownerPrincipalId || operation.requestId !== requestId) throw new TypeError('endpoint operation index differs');
    const object = (ref: string) => {
      const bytes = endpointObject(held, ref);
      const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('endpoint identity object is not canonical');
      return value;
    };
    const channel = decodeControlChannel(object(operation.channelIdentityRef));
    const principal = decodeLocalPrincipalIdentity(object(channel.principalIdentityRef));
    const root = decodeStateRootIdentity(object(principal.stateRootIdentityRef));
    if (channel.transport.kind !== 'in_process') throw new TypeError('endpoint channel is not the installed in-process transport');
    const processIdentity = decodePlatformProcessIdentity(object(channel.transport.processIdentityRef));
    if (channel.channelIdentityDigest !== operation.channelIdentityDigest || channel.principalId !== held.ownerPrincipalId || channel.client !== 'cli' ||
        principal.identityDigest !== channel.principalIdentityDigest || principal.principalId !== held.ownerPrincipalId ||
        principal.stateRootIdentityDigest !== root.identityDigest || canonicalSha256(root) !== canonicalSha256(held.rootIdentity) ||
        principal.platform !== root.platform || principal.effectiveUid !== root.ownerUid || processIdentity.platform !== root.platform ||
        processIdentity.ownerUid !== root.ownerUid || processIdentity.identityDigest !== channel.transport.processIdentityDigest ||
        processIdentity.executableImageDigest !== held.processIdentity.executableImageDigest || processIdentity.observedAt !== channel.openedAt ||
        parseCanonicalTime(operation.committedAt) < parseCanonicalTime(channel.openedAt)) throw new TypeError('endpoint channel closure differs');
    return operation;
  } catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'retained endpoint operation provenance could not be verified', { cause }); }
}

function validateEndpointResult(operation: EndpointAuthorityOperationV1, history: readonly EndpointAuthorityRecordV1[]): void {
  const record = history[operation.committedAuthorityRevision - 1];
  const core = operation.commandCore;
  if (!record || record.recordDigest !== operation.resultRecordDigest || record.ownerPrincipalId !== operation.ownerPrincipalId ||
      record.endpointRegistrationId !== operation.endpointRegistrationId ||
      parseCanonicalTime(operation.committedAt) < parseCanonicalTime(record.state === 'revoked' ? record.revokedAt : record.createdAt))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint operation historical result differs');
  if (core.kind === 'register') {
    if (record.state !== 'active' || record.expectedRegistrationArtifactRef !== core.expectedRegistrationArtifactRef ||
        !canonicalJsonBytes(record.registration).equals(canonicalJsonBytes(core.registration)) ||
        (operation.disposition === 'registered' && (record.sourceRequestId !== operation.requestId || record.sourceRequestDigest !== operation.requestDigest ||
          record.createdAt !== operation.committedAt))) throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint registration result differs');
  } else if (record.state !== 'revoked' || (operation.disposition === 'revoked' &&
      (core.expectedAuthorityRevision !== 1 || record.revokedByRequestId !== operation.requestId || record.revokedByRequestDigest !== operation.requestDigest ||
        record.revokedAt !== operation.committedAt))) throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint revocation result differs');
}

function readEndpointHistory(held: CredentialBinding, endpointId: string): EndpointAuthorityRecordV1[] {
  try {
    const rows = held.database!.prepare(`SELECT authority_revision,record_json FROM endpoint_records
      WHERE owner_principal_id=? AND endpoint_registration_id=? ORDER BY authority_revision LIMIT 3`).all(held.ownerPrincipalId, endpointId);
    if (rows.length > 2) throw new TypeError('endpoint history contains extra revisions');
    const history = rows.map((row, index) => {
      const record = endpointJson(row.record_json, decodeEndpointAuthorityRecord);
      if (record.ownerPrincipalId !== held.ownerPrincipalId || record.endpointRegistrationId !== endpointId ||
          record.authorityRevision !== index + 1 || record.authorityRevision !== row.authority_revision)
        throw new TypeError('endpoint history index or continuity differs');
      verifyEndpointTrust(held, record.registration, true);
      return record;
    });
    if (!history.length) {
      // An orphan operation must not make a deleted endpoint look unregistered.
      const orphan = held.database!.prepare(`SELECT 1 FROM endpoint_operations WHERE owner_principal_id=?
        AND json_extract(operation_json,'$.endpointRegistrationId')=? LIMIT 1`).get(held.ownerPrincipalId, endpointId);
      if (orphan) throw new TypeError('endpoint operation has no retained result');
      return history;
    }
    const first = history[0]!;
    const source = readEndpointOperation(held, first.sourceRequestId);
    if (first.state !== 'active' || first.registration.registrationKind !== 'user' || !source || source.disposition !== 'registered' || source.requestDigest !== first.sourceRequestDigest ||
        parseCanonicalTime(first.registration.createdAt) > parseCanonicalTime(first.createdAt)) throw new TypeError('endpoint registration source is missing or invalid');
    validateEndpointResult(source, history);
    const revoked = history[1];
    if (revoked) {
      if (revoked.state !== 'revoked' || parseCanonicalTime(revoked.revokedAt) < parseCanonicalTime(first.createdAt))
        throw new TypeError('endpoint terminal revision or revocation time differs');
      const { recordDigest: _firstDigest, ...original } = first;
      const { recordDigest: _revokedDigest, ...actual } = revoked;
      if (!canonicalJsonBytes(actual).equals(canonicalJsonBytes({ ...original, authorityRevision: 2, state: 'revoked',
        revokedAt: revoked.revokedAt, revokedByRequestId: revoked.revokedByRequestId, revokedByRequestDigest: revoked.revokedByRequestDigest })))
        throw new TypeError('endpoint revocation rewrites original registration or source');
      const operation = readEndpointOperation(held, revoked.revokedByRequestId);
      if (!operation || operation.disposition !== 'revoked' || operation.requestDigest !== revoked.revokedByRequestDigest)
        throw new TypeError('endpoint revocation source is missing or invalid');
      validateEndpointResult(operation, history);
    }
    return history;
  } catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'retained endpoint history could not be verified', { cause }); }
}

/** Fixed internal friend of the installed producer. Only its inaccessible,
 * WeakMap-branded physical scope reaches this runner. Open the fixed MAIN lease
 * before invoking the business callback; never expose a pre-DB physical borrow,
 * SQL, a structural native/owner registration or a configurable time source. */
export async function runInstalledCredentialAuthority<T>(physical: InstalledCredentialScope,
  operation: (token: HeldCredentialAuthorityLock) => Promise<T>): Promise<T> {
  const binding: CredentialBinding = { ...installedCredentialProvenance(physical), physical, active: true };
  const token: HeldCredentialAuthorityLock = Object.freeze({ assertHeld() {
    if (this !== token) throw new TypeError('invalid credential authority token receiver');
    checkedCredentialToken(token);
  } });
  credentialTokens.set(token, binding);
  let database: DatabaseSync | undefined;
  let failed = false;
  let failure: unknown;
  let result: T;
  try {
    token.assertHeld();
    database = new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-v1', { allowExtension: false });
    if (database.prepare('PRAGMA locking_mode=EXCLUSIVE').get()?.locking_mode !== 'exclusive')
      throw new KernelStorageError('RECOVERY_REQUIRED', 'credential authority requires exclusive pager mode');
    database.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA busy_timeout=0');
    if (database.prepare('PRAGMA journal_mode=WAL').get()?.journal_mode !== 'wal')
      throw new KernelStorageError('RECOVERY_REQUIRED', 'credential authority requires fixed exclusive-mode WAL');
    // Initialize the real transaction facility without inventing a schema,
    // endpoint, platform observation or authenticated business authority.
    database.exec('BEGIN IMMEDIATE; COMMIT');
    binding.database = database;
    token.assertHeld();
    result = await operation(token);
    token.assertHeld();
  } catch (error) { failed = true; failure = error; }
  finally {
    binding.active = false;
    binding.database = undefined;
    try { database?.close(); }
    catch (error) { throw new ResourceRetirementError('credential authority database did not retire',
      new AggregateError(failed ? [failure, error] : [error])); }
  }
  if (failed) throw failure;
  return result!;
}

/** Trusted Supervisor bootstrap input, never loaded from Run/workspace configuration. Required again on signed-owner reopen. */
export type StateStoreRuntimeAuthority = { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[];
  execution?: RunExecutionInstallation;
  sourceInspection?: { controlledHome: string; sandboxProfile: SandboxProfileV1 } };

export type CaptureSubmittedSourceInput = Readonly<{ request: unknown; identity: AuthenticatedControlIdentity }>;
type SourceInspectionTask = { abort: AbortController; promise: Promise<SourceInspectionAttemptV1> };

export type {
  LoadAgentRunInput,
  ActivateWorkerLeaseInput,
  AdmitRunInput,
  AdmitRunResult,
  BeginGenerationCheckpointInput,
  BeginGenerationRevocationInput,
  BeginWorkerRecoveryInput,
  ClaimInvocationDispatchInput,
  CreateSessionInput,
  CreateSessionResult,
  PrepareInvocationInput,
  RecordWorkerPreactivatedInput,
  RecordWorkspaceGenerationPreactivatedInput,
  RegisterWorkspaceGenerationInput,
  RenewWorkerLeaseInput,
  ReserveWorkerLaunchInput,
  SealWorkerGenerationInput,
  SettleInvocationInput
};

function assertFreshAuthorityDatabaseEmpty(connection: SqliteConnection | SqliteDriver): void {
  for (const table of KERNEL_AUTHORITY_TABLES) {
    const row = connection
      .prepare(`SELECT count(*) AS count FROM ${table}`)
      .get<{ count: unknown }>();
    if (Number(row?.count ?? 0) !== 0) {
      throw new KernelStorageError(
        'RECOVERY_REQUIRED',
        `refusing fresh genesis over non-empty authority table ${table}`
      );
    }
  }
}

function requireEffectiveUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'state store requires a POSIX effective uid');
  }
  return process.geteuid();
}

async function currentProcessIdentity(native: NativeStateOwner, observedAt: string): Promise<PlatformProcessIdentityV1> {
  const base = await native.observeCurrentProcess();
  const identity: PlatformProcessIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-platform-process-identity-v1',
    platform: hostPlatform(),
    pid: base.pid,
    processStartToken: base.processStartToken,
    ownerUid: base.uid,
    executableImageDigest: base.executableImageDigest,
    observedAt,
    identityDigest: ''
  };
  identity.identityDigest = digestOmitting(identity, 'identityDigest');
  return identity;
}

async function assertPrivateStateRoot(stateRoot: string): Promise<void> {
  let normalized: string;
  try {
    normalized = normalizeAbsolutePath(stateRoot);
  } catch {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be a normalized absolute path');
  }
  if (normalized !== stateRoot) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be a normalized absolute path');
  }
  const info = await lstat(stateRoot);
  if (info.isSymbolicLink()) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must not be a symbolic link');
  }
  if (!info.isDirectory()) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be a directory');
  }
  if (info.uid !== requireEffectiveUid()) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be owned by the effective uid');
  }
  if ((info.mode & 0o7777) !== 0o700) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root mode must be exactly 0700');
  }
}

async function ensurePrivateDirectory(directory: string, allowCreate: boolean): Promise<void> {
  let existing: Stats;
  try {
    existing = await lstat(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    if (!allowCreate) {
      throw new KernelStorageError(
        'RECOVERY_REQUIRED',
        `${directory} is missing from an existing StateOwner generation`
      );
    }
    await mkdir(directory, { mode: 0o700 });
    existing = await lstat(directory);
  }
  if (existing.isSymbolicLink() || !existing.isDirectory()) {
    throw new KernelStorageError('INVALID_REQUEST', `${directory} must be a 0700 directory`);
  }
  if (existing.uid !== requireEffectiveUid()) {
    throw new KernelStorageError('INVALID_REQUEST', `${directory} must be owned by the effective uid`);
  }
  const info = await lstat(directory);
  if (
    info.isSymbolicLink() ||
    !info.isDirectory() ||
    info.uid !== requireEffectiveUid() ||
    (info.mode & 0o7777) !== 0o700
  ) {
    throw new KernelStorageError('INVALID_REQUEST', `${directory} must be a 0700 directory`);
  }
}

async function stateOwnerFilesystemFromArtifacts(
  stateRoot: string,
  artifacts: ArtifactCatalog,
  owner: StateOwnerRecordV1,
  heldLock: HeldStateOwnerLock
): Promise<{
  lockIdentity: StateLockIdentityV1;
  filesystem: StateOwnerContext['filesystem'];
}> {
  const lockIdentity = decodeStateLockIdentity(
    await artifacts.readCanonical(owner.stateLockIdentityRef)
  );
  if (lockIdentity.identityDigest !== owner.stateLockIdentityDigest) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner lock identity does not rehash');
  }
  const rootIdentity = decodeStateRootIdentity(
    await artifacts.readCanonical(lockIdentity.stateRootIdentityRef)
  );
  if (
    rootIdentity.identityDigest !== lockIdentity.stateRootIdentityDigest ||
    rootIdentity.canonicalAbsolutePath !== stateRoot ||
    rootIdentity.ownerUid !== requireEffectiveUid() ||
    rootIdentity.platform !== hostPlatform() ||
    lockIdentity.ownerUid !== requireEffectiveUid()
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner root identity does not rehash');
  }
  assertStateOwnerLock(heldLock);
  if (
    heldLock.root.deviceId !== rootIdentity.deviceId ||
    heldLock.root.fileId !== rootIdentity.directoryFileId ||
    heldLock.lock.deviceId !== lockIdentity.deviceId ||
    heldLock.lock.fileId !== lockIdentity.fileId
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner filesystem identity changed during open');
  }
  return {
    lockIdentity,
    filesystem: heldLock
  };
}

async function stateOwnerContextFromArtifacts(
  stateRoot: string,
  artifacts: ArtifactCatalog,
  owner: Extract<StateOwnerRecordV1, { state: 'active' }>,
  heldLock: HeldStateOwnerLock
): Promise<StateOwnerContext> {
  const { lockIdentity, filesystem } = await stateOwnerFilesystemFromArtifacts(
    stateRoot,
    artifacts,
    owner,
    heldLock
  );
  await readStateOwnerProcess(artifacts, owner);
  return contextFromStateOwner(
    owner,
    filesystem,
    { ref: lockIdentity.stateRootIdentityRef, digest: lockIdentity.stateRootIdentityDigest }
  );
}

// Failed opening has no Store for a caller to close. Keep uncertain resources
// strongly owned until actual process death; skipping close alone would let
// the native finalizer release the flock after GC. This is resource retention,
// not another durable lifecycle or a permission to retry the failed opening.
const unretiredStateStoreOpenings = new Set<Readonly<{
  lock: HeldStateOwnerLock; driver: SqliteDriver | undefined; failure: ResourceRetirementError;
}>>();

function failStateStoreOpening(lock: HeldStateOwnerLock, driver: SqliteDriver | undefined, error: unknown): never {
  let failure = error;
  if (!(error instanceof ResourceRetirementError)) {
    try {
      // SQLite must close before the flock; a failed close proves neither
      // database retirement nor permission to release the actual owner.
      driver?.close();
      lock.close();
    } catch (cause) {
      failure = new ResourceRetirementError('StateStore opening resources did not retire',
        new AggregateError([error, cause]));
    }
  }
  if (failure instanceof ResourceRetirementError)
    unretiredStateStoreOpenings.add(Object.freeze({ lock, driver, failure }));
  throw failure;
}

// A rejected close can outlive the caller too. GC is not a successful join;
// release this strong owner only after the exact close actually succeeds.
const unretiredStateStoreClosings = new Set<StateStore>();

type InstalledCredentialFinalizer = { driver: SqliteDriver; owner: StateOwnerContext; selected: HeldInstalledRuntime;
  active: boolean; task?: Promise<CredentialAuthorityOperationV1>; inspection?: NativeCredentialInspection;
  inspectionJoin?: Promise<void>; retirementFailure?: ResourceRetirementError };
const installedCredentialFinalizers = new WeakMap<StateStore, InstalledCredentialFinalizer>();

/** Private physical producer registry. Entries outlive ordinary caller errors
 * until every actual native preparation/release/retirement has joined. */
type InstalledBrokerOwner = { driver: SqliteDriver; owner: StateOwnerContext;
  operations: Map<string, Promise<unknown>>; transports: Map<string, NativeModelTransport>;
  settlements: ReadonlyMap<string, unknown> };
const installedBrokerOwners = new WeakMap<StateStore, InstalledBrokerOwner>();
export type InstalledBrokerQuiescence = Readonly<{ assertHeld(): void }>;
const installedBrokerQuiescences = new WeakMap<InstalledBrokerQuiescence, { store: StateStore; binding: InstalledBrokerOwner; runId: string }>();

export function assertInstalledBrokerQuiescence(receipt: InstalledBrokerQuiescence, driver: SqliteDriver,
  owner: StateOwnerContext, runId: string): void {
  const observed = installedBrokerQuiescences.get(receipt);
  if (!observed || installedBrokerOwners.get(observed.store) !== observed.binding || observed.binding.driver !== driver ||
      observed.binding.owner !== owner || observed.runId !== runId)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'broker quiescence has no original physical Store owner');
  // Physical registry assertion only. The consumer checks active StateOwner
  // and row predicates through its actual transaction-scoped SQL connection.
  assertStateOwnerLock(owner.filesystem);
  if (observed.binding.operations.has(runId) || observed.binding.transports.has(runId) || observed.binding.settlements.has(runId))
    throw new ResourceRetirementError('generation retains an original native model transport owner', undefined);
}

/** No counts, callbacks, fake Store or supplied claim evidence can mint it. */
export function observeInstalledBrokerQuiescence(store: StateStore, runId: string): InstalledBrokerQuiescence {
  const binding = installedBrokerOwners.get(store);
  if (!binding) throw new KernelStorageError('ARTIFACT_MISMATCH', 'broker retirement requires the genuine StateStore');
  assertActiveStateOwner(binding.driver, binding.owner); readRun(binding.driver, runId);
  const receipt: InstalledBrokerQuiescence = Object.freeze({ assertHeld() {
    if (this !== receipt) throw new TypeError('invalid broker quiescence receiver');
    assertInstalledBrokerQuiescence(receipt, binding.driver, binding.owner, runId);
  } });
  installedBrokerQuiescences.set(receipt, { store, binding, runId }); receipt.assertHeld(); return receipt;
}

export class StateStore {
  private closed = false;
  private released = false;
  private closeRequested = false;
  private closing: Promise<void> | undefined;
  private closeRevocationFailure: ResourceRetirementError | undefined;
  private readonly controlListeners = new Set<LocalControlListener>();
  // Reserve the Run through validation and join that opening during shutdown.
  // This protects resources; SQLite remains the sole lifecycle authority.
  private readonly executions = new Map<string, Promise<Awaited<ReturnType<typeof loadRunExecution>>>>();
  private readonly loadedExecutionScopes = new Map<string, Awaited<ReturnType<typeof loadRunExecution>>>();
  private readonly sourceInspectionTasks = new Set<SourceInspectionTask>();
  private readonly sourceInspections = new Map<string, { intent: string; task: SourceInspectionTask }>();
  private readonly installedAdmissionTasks = new Set<{ abort: AbortController; promise: Promise<unknown> }>();
  private readonly modelTransports = new Map<string, NativeModelTransport>();
  private readonly modelOperations = new Map<string, Promise<unknown>>();
  // A positively received result keeps its original settlement owner through
  // CAS/storage refusal. Maintenance may retry settlement, never network I/O.
  private readonly installedModelCompletions = new Map<string, {
    prepared: InvocationJournalEntry; claimed: InvocationJournalEntry; result: ModelAttemptResult;
  }>();
  // Original joined transports remain owned until their typed failure
  // settlement commits. A storage refusal never disposes the only live fence.
  private readonly installedModelClosures = new Map<string, {
    prepared: InvocationJournalEntry; claimed: InvocationJournalEntry; transport: NativeModelTransport;
    closure?: ModelBrokerClosed; initial: Awaited<ReturnType<typeof readModelClaimCut>>;
  }>();
  private readonly installedRunTasks = new Map<string, Promise<void>>();
  private readonly installedRunPhases = new Map<string, RunResultPhase | RunPublicationPhase | 'scheduled' | 'drive_material' | 'drive_agent' |
    'drive_retirement' | `drive_retirement_${RunRetirementPhase}` | 'drive_verify' | 'drive_finalize' | 'terminal_retirement'>();
  private readonly installedAgents = new Map<string, { agent: InstalledContinuation; readAbort: AbortController }>();
  private readonly installedAgentLoads = new Map<string, Promise<InstalledContinuation>>();
  private readonly installedRunFailures = new Map<string, unknown>();
  private readonly installedPreparationRetries = new Map<string, { error: KernelStorageError | CredentialScopeBusyError; opId: string; attempt: number;
    preparedSeq: number; failedSeq: number; requestRef: string; settlementRef: string }>();
  private schedulerStarted = false;
  private installedModelAdmissionReady = false;
  private schedulerFailure: unknown;
  private installedQueue = Promise.resolve();
  private installedMaintenanceTimer?: ReturnType<typeof setTimeout>;
  private installedMaintenance?: Promise<void>;

  private constructor(
    readonly stateRoot: string,
    private readonly driver: SqliteDriver,
    readonly artifacts: ArtifactCatalog,
    private readonly owner: StateOwnerContext,
    private readonly runtimeAuthority?: StateStoreRuntimeAuthority,
    private readonly installedRuntime?: HeldInstalledRuntime,
    private readonly installedAnchor?: HeldInstalledAnchor
  ) {
    // This observes only the Store's real producer registry, including an
    // empty tool-only Store. It grants no installed/model execution authority.
    installedBrokerOwners.set(this, { driver, owner,
      operations: this.modelOperations, transports: this.modelTransports, settlements: this.installedModelCompletions });
  }

  get ownerEpoch(): number {
    return this.owner.ownerEpoch;
  }
  supportsCredentialFinalization(): boolean { return installedCredentialFinalizers.has(this); }
  supportsInstalledRuns(): boolean { return this.schedulerStarted && this.schedulerFailure === undefined && !this.closeRequested && !this.closed; }
  supportsInstalledDelivery(): boolean { return INSTALLED_DELIVERY_COMPOSITION_COMPLETE && this.supportsInstalledRuns(); }
  supportsSessionContinuity(): boolean { return !this.closed && !this.closeRequested && !this.released; }

  sessionContinuity(request: unknown, identity: AuthenticatedControlIdentity) {
    if (!this.supportsSessionContinuity()) return Promise.reject(new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed'));
    request = immutableSnapshot(request);
    return this.ownInstalledAdmission(async signal => {
      const { decodeSessionContinuityRequest } = await import('../kernel/session-continuity.js');
      const decoded = decodeSessionContinuityRequest(request), scoped = this.artifacts.withReadSignal(signal);
      signal.throwIfAborted();
      if (decoded.method === 'session.list') {
        const { readSessionList } = await import('./list-read-cut.js');
        return { protocolVersion: 1 as const, ok: true as const, result: await readSessionList(this.driver, scoped, this.owner, decoded, identity, signal) };
      }
      const { mutateSessionContext, createSessionHandoff } = await import('./session-continuity.js');
      signal.throwIfAborted();
      if (decoded.method === 'session.handoff.create') return { protocolVersion: 1 as const, ok: true as const,
        result: await createSessionHandoff(this.driver, scoped, this.owner, decoded, identity, signal) };
      return mutateSessionContext(this.driver, scoped, this.owner, decoded, identity, signal);
    });
  }

  createAuthorization(request: unknown, identity: AuthenticatedControlIdentity) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return this.ownInstalledAdmission(async signal => {
      signal.throwIfAborted();
      const { createAuthorization } = await import('./authorization.js');
      signal.throwIfAborted();
      return createAuthorization(this.driver, this.artifacts, this.owner, this.runtimeAuthority, request, identity, signal);
    });
  }

  revokeAuthorization(request: unknown, identity: AuthenticatedControlIdentity) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return this.ownInstalledAdmission(async signal => {
      signal.throwIfAborted();
      const { revokeAuthorization } = await import('./authorization.js');
      signal.throwIfAborted();
      return revokeAuthorization(this.driver, this.artifacts, this.owner, this.runtimeAuthority, request, identity, signal);
    });
  }

  async createInstalledSession(request: unknown, identity: AuthenticatedControlIdentity) {
    if (!this.supportsInstalledRuns() || !this.installedRuntime || !this.runtimeAuthority?.sourceInspection)
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed Run composition is not ready');
    request = immutableSnapshot(request);
    const selected = this.installedRuntime, controlledHome = this.runtimeAuthority.sourceInspection.controlledHome;
    return this.ownInstalledAdmission(signal => createInstalledSession(this.driver, this.artifacts, this.owner,
      request, identity, selected, controlledHome, signal));
  }

  async submitInstalledRun(request: unknown, identity: AuthenticatedControlIdentity) {
    if (!this.supportsInstalledRuns() || !this.installedRuntime || !this.runtimeAuthority?.sourceInspection)
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed Run composition is not ready');
    request = immutableSnapshot(request);
    return this.ownInstalledAdmission(signal => this.submitInstalledRunOwned(request, identity, signal));
  }

  async applyInstalledRun(request: unknown, identity: AuthenticatedControlIdentity) {
    if (!this.supportsInstalledDelivery() || !this.installedRuntime || !this.runtimeAuthority?.sourceInspection)
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed delivery composition is not complete');
    request = immutableSnapshot(request);
    return this.ownInstalledAdmission(signal => this.applyInstalledRunOwned(request, identity, signal));
  }

  async approveInstalledRun(request: unknown, identity: AuthenticatedControlIdentity) {
    if (!this.supportsInstalledDelivery()) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed delivery composition is not complete');
    const value = decodeInstalledControlRequest(request);
    if (value.method !== 'run.approve') throw new KernelStorageError('INVALID_REQUEST', 'approval requires its exact public contract');
    return this.ownInstalledAdmission(async signal => {
      await validateControlChannelClosure(this.artifacts, this.owner, identity); signal.throwIfAborted();
      const selected = readRun(this.driver, value.runId);
      if (decodeRunSpec(await this.artifacts.withReadSignal(signal).readCanonical(selected.specRef)).operation !== 'delivery')
        throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed approval is connected only for delivery');
      const continuation = await this.retainInstalledAgent(value.runId);
      if (continuation.operation !== 'delivery') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed approval is connected only for delivery');
      const result = await continuation.approveDelivery({ ...identity, requestId: value.requestId, expectedRunRevision: value.expectedRevision,
        waitingOnRef: value.waitingOnRef, decision: value.decision, ...(value.ttlMs === undefined ? {} : { ttlMs: value.ttlMs }) });
      if (result.run.stopIntentRef) this.requestInstalledRunStop(value.runId);
      this.scheduleInstalledRun(value.runId); return result;
    });
  }

  async reconcileInstalledRun(request: unknown, identity: AuthenticatedControlIdentity) {
    if (!this.supportsInstalledDelivery()) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed delivery composition is not complete');
    const value = decodeInstalledControlRequest(request);
    if (value.method !== 'run.reconcile') throw new KernelStorageError('INVALID_REQUEST', 'reconciliation requires its exact public contract');
    return this.ownInstalledAdmission(async signal => {
      const reconciliation = await import('./publication-reconciliation.js');
      const replay = await reconciliation.replayPublicationReconciliationProbe(this.driver, this.artifacts.withReadSignal(signal),
        this.owner, { request: value, identity });
      signal.throwIfAborted();
      if (replay) return { run: replay.run, response: replay.response };
      const current = readRun(this.driver, value.runId);
      if (readSessionPrincipalId(this.driver, current.sessionId) !== identity.principalId)
        throw new KernelStorageError('NOT_FOUND', 'publication Run is unavailable');
      if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(current.status)) throw new RunTerminalError();
      if (current.revision !== value.expectedRevision)
        throw new KernelStorageError('REVISION_CONFLICT', 'publication probe Run revision changed');
      if (current.status !== 'waiting' || current.waitingReason !== 'reconciliation' || current.waitingOnRef !== value.waitingOnRef ||
          decodeRunSpec(await this.artifacts.withReadSignal(signal).readCanonical(current.specRef)).operation !== 'delivery')
        throw new KernelStorageError('INVALID_REQUEST', 'probe_now requires its exact current publication wait');
      // The reducer authenticates the frame and original principal before any
      // enqueue. Only this Store supplies the genuine execution/task owner;
      // the public request has no target, evidence or authority fields.
      const execution = await this.loadRunExecution({ runId: value.runId, operation: 'delivery' });
      signal.throwIfAborted();
      const result = await execution.enqueuePublicationReconciliation({ request: value, identity });
      // Acknowledgement is only the committed enqueue. The actual producer
      // remains in the execution's original pending scope and is joined by
      // Store shutdown; this observer reports failures, not cleanup evidence.
      void result.completion.then(() => this.scheduleInstalledRun(value.runId), error => {
        this.installedRunFailures.set(value.runId, error);
        const diagnosis = beginInstalledSchedulerDiagnostic('publication_recovery');
        diagnosis?.phase(this.installedRunPhases.get(value.runId));
        diagnosis?.failure(error, this.closeRequested);
        if (error instanceof ResourceRetirementError) this.schedulerFailure ??= error;
        else this.scheduleInstalledRun(value.runId);
      });
      return { run: result.run, response: result.response };
    });
  }

  private async applyInstalledRunOwned(request: unknown, identity: AuthenticatedControlIdentity, signal: AbortSignal) {
    const diagnosis = beginInstalledApplyDiagnostic();
    try {
      signal.throwIfAborted();
      const normalized = normalizeRunApplyRequest(request);
      await validateControlChannelClosure(this.artifacts, this.owner, identity);
      diagnosis?.stage('replay');
      const replay = await replayInstalledDeliveryAdmission(this.driver, this.artifacts.withReadSignal(signal), this.owner, normalized, identity, signal);
      if (replay) {
        if (['queued', 'running', 'waiting'].includes(readRun(this.driver, replay.run.id).status)) {
          diagnosis?.stage('postcommit_load');
          this.retainInstalledAgent(replay.run.id);
        }
        this.scheduleInstalledRun(replay.run.id); return replay;
      }
      diagnosis?.stage('capture_source');
      const capture = await this.captureSubmittedSource({ request, identity }, diagnosis);
      if (capture.phase !== 'retired') throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery source inspection has not completely retired');
      if (capture.outcome.kind !== 'captured') {
        const { readSourceInspectionErrorResponse } = await import('./source-inspection-owner.js');
        const response = await readSourceInspectionErrorResponse(this.artifacts.withReadSignal(signal), capture);
        await validateControlChannelClosure(this.artifacts, this.owner, identity);
        signal.throwIfAborted(); assertCurrentControlFrame(this.owner, identity); assertActiveStateOwner(this.driver, this.owner);
        return { response };
      }
      diagnosis?.stage('source');
      const source = await readVerifiedDeliverySource(this.driver, this.artifacts.withReadSignal(signal), this.owner, {
        principalId: identity.principalId, sourceRunId: normalized.request.sourceRunId,
        expectedRunResultRef: normalized.request.expectedRunResultRef, signal });
      diagnosis?.stage('prepare');
      const prepared = await prepareInstalledDelivery({ driver: this.driver, artifacts: this.artifacts, owner: this.owner,
        selected: this.installedRuntime!, request, identity, source, capture }, signal);
      diagnosis?.stage('admit');
      const admission = admitInstalledDelivery(this.driver, this.artifacts, this.owner, prepared, identity, signal);
      const runId = identityHash('cliq-run-id-v1', identity.principalId, 'run.apply', normalized.request.admissionKey);
      this.retainInstalledAgent(runId, undefined, admission);
      const result = await admission;
      diagnosis?.stage('postcommit_load');
      this.scheduleInstalledRun(result.run.id); return result;
    } catch (error) {
      diagnosis?.failure(error, this.closeRequested);
      throw error;
    }
  }

  private ownInstalledAdmission<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    // Each caller snapshots request data and retains the exact identity
    // object already frozen and authenticated by the native current frame.
    const abort = new AbortController();
    // Own the complete handler before its first asynchronous action, not only
    // its Trust/source leaf. Session capture, Run assembly, admission/replay
    // and any accepted Run agent load must join before StateOwner is released.
    let enter!: () => void;
    const promise = new Promise<T>((resolve, reject) => {
      enter = () => { try { resolve(operation(abort.signal)); } catch (error) { reject(error); } };
    });
    const task = { abort, promise }; this.installedAdmissionTasks.add(task);
    const release = (error?: unknown) => {
      if (!(error instanceof ResourceRetirementError)) this.installedAdmissionTasks.delete(task);
    };
    void promise.then(() => release(), release);
    // Register before entry, but do not queue that entry in another microtask:
    // each real producer snapshots its caller-owned inputs synchronously before
    // its first await. Deferring entry would reopen an authority-mutation race.
    enter();
    return promise;
  }

  private async submitInstalledRunOwned(request: unknown, identity: AuthenticatedControlIdentity, signal: AbortSignal) {
    const diagnosis = beginInstalledSubmitDiagnostic();
    try {
      signal.throwIfAborted();
      const reads = this.artifacts.withReadSignal(signal);
      if (!this.installedRuntime || !this.runtimeAuthority?.sourceInspection)
        throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed Run composition is not ready');
      const normalized = normalizeRunSubmitRequest(request);
      diagnosis?.stage('submit_preflight_authority');
      await validateControlChannelClosure(reads, this.owner, identity);
      signal.throwIfAborted();
      const { replayInstalledRunAdmission, admitInstalledRun } = await import('./reducers/admission.js');
      const replay = await replayInstalledRunAdmission(this.driver, this.artifacts, this.owner, normalized, identity, this.runtimeAuthority, signal);
      if (replay) {
        if ('run' in replay) {
          if (['queued', 'running', 'waiting'].includes(readRun(this.driver, replay.run.id).status)) {
            diagnosis?.stage('submit_postcommit_load');
            this.retainInstalledAgent(replay.run.id);
          }
          this.scheduleInstalledRun(replay.run.id);
        }
        return replay;
      }
      const { readSourceInspectionAttempt } = await import('./source-inspection.js');
      const sourceKey = { principalId: identity.principalId, admissionKey: normalized.request.admissionKey,
        admissionIntentDigest: runSubmitIntentDigest(identity.principalId, normalized.request) };
      const retainedSource = readSourceInspectionAttempt(this.driver, sourceKey);
      if (retainedSource?.phase === 'retired' && retainedSource.outcome.kind !== 'captured') {
        // Return only an inert historical refusal before new admission preflight.
        // The retained-only producer validates its full historical closure and
        // binds a fresh request id; it can never fall back to recapture.
        const { replaySubmittedSource, readSourceInspectionErrorResponse } = await import('./source-inspection-owner.js');
        assertCurrentControlFrame(this.owner, identity); assertActiveStateOwner(this.driver, this.owner);
        const source = await replaySubmittedSource(this.driver, reads, this.owner,
          { bundle: this.runtimeAuthority.bundle, releaseKeys: this.runtimeAuthority.releaseKeys,
            ...this.runtimeAuthority.sourceInspection, sandboxProfile: installedSandboxProfile(normalized.request.sandboxResources) },
          normalized.request, identity);
        if (!source || canonicalSha256(source) !== canonicalSha256(retainedSource))
          throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run source refusal changed during retained replay');
        const response = await readSourceInspectionErrorResponse(reads, source);
        await validateControlChannelClosure(reads, this.owner, identity);
        assertCurrentControlFrame(this.owner, identity); assertActiveStateOwner(this.driver, this.owner);
        const currentSource = readSourceInspectionAttempt(this.driver, sourceKey);
        if (!currentSource || canonicalSha256(currentSource) !== canonicalSha256(retainedSource))
          throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run source refusal changed before replay response');
        return { response };
      }
      const { assembleInstalledRun, assertInstalledRunRecipe, InstalledRunAuthorityError } = await import('./installed-run.js');
      if (!this.installedModelAdmissionReady) throw new InstalledRunAuthorityError('MODEL_CAPABILITY_UNKNOWN');
      const assertRecipe: typeof assertInstalledRunRecipe = assertInstalledRunRecipe;
      assertRecipe(normalized.request);
      const model = normalized.request.model;
      if (model.provider !== 'openai-compatible') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed Run requires its fixed signed model recipe');
      const selected = this.installedRuntime, controlledHome = this.runtimeAuthority.sourceInspection.controlledHome;
      // Refuse invalid credential intent before publishing source or assembly
      // CAS objects. This read is not the final admission or release authority.
      const authority = await withCredentialAuthorityLock(selected, async token => {
        signal.throwIfAborted();
        const held = checkedCredentialToken(token);
        const authority = currentModelAuthority(held, identity.principalId, model.endpoint.endpointRegistrationId,
          model.modelCredentialGrantIds, sampleCanonicalNow());
        return immutableSnapshot({ endpoint: authority.endpoint, bindings: authority.bindings });
      });
      signal.throwIfAborted();
      assertRecipe(normalized.request, authority.endpoint);
      diagnosis?.stage('submit_source_capture');
      const source = await this.captureSubmittedSource({ request, identity });
      if (source.phase !== 'retired') throw new KernelStorageError('RECOVERY_REQUIRED', 'Run source inspection has not completely retired');
      if (source.outcome.kind !== 'captured') {
        const { readSourceInspectionErrorResponse } = await import('./source-inspection-owner.js');
        const response = await readSourceInspectionErrorResponse(reads, source);
        await validateControlChannelClosure(reads, this.owner, identity);
        assertCurrentControlFrame(this.owner, identity); assertActiveStateOwner(this.driver, this.owner);
        return { response };
      }
      // Installation borrows and the credential pager share an intentionally
      // non-reentrant physical queue. Prepare immutable data outside its lock;
      // reacquire and check the exact current revisions for the final admission.
      diagnosis?.stage('submit_assembly');
      const assembled = await assembleInstalledRun({ selected, driver: this.driver, owner: this.owner,
        artifacts: this.artifacts, identity, request: normalized.request, originalRequest: normalized.originalRequest, source,
        endpoint: authority.endpoint, credentialBindings: authority.bindings, controlledHome }, signal, diagnosis?.stage);
      diagnosis?.stage('submit_final_admission');
      const admission = withCredentialAuthorityLock(selected, async token => {
        signal.throwIfAborted();
        const held = checkedCredentialToken(token);
        currentModelAuthority(held, identity.principalId, model.endpoint.endpointRegistrationId,
          model.modelCredentialGrantIds, sampleCanonicalNow(), authority);
        if (authority.bindings.some(binding => binding.expiresAt !== undefined && binding.expiresAt < assembled.deadlineAt))
          throw new InstalledModelAuthorizationError();
        assertCurrentControlFrame(this.owner, identity); token.assertHeld();
        return admitInstalledRun(this.driver, this.artifacts, this.owner, assembled, identity, this.runtimeAuthority, signal);
      });
      const runId = identityHash('cliq-run-id-v1', identity.principalId, 'run.submit', normalized.request.admissionKey);
      // Register before that asynchronous producer can commit a visible Run.
      // Maintenance joins the same load, never waiting on its own credential
      // queue or misclassifying an in-flight admission as corrupt state.
      this.retainInstalledAgent(runId, assembled.material, admission);
      const result = await admission;
      diagnosis?.stage('submit_postcommit_load');
      // The Run and original response are durable. Its independently owned
      // load is joined by the existing driver before any productive action;
      // attachment does not own that load or delay durable acknowledgement.
      this.scheduleInstalledRun(result.run.id);
      return result;
    } catch (error) {
      diagnosis?.failure(error, this.closeRequested);
      throw error;
    }
  }

  /** One bounded production lane, reconstructing retained Runs rather than
   * maintaining another lifecycle ledger. No client connection owns its task. */
  async startInstalledRuns(): Promise<void> {
    if (this.schedulerStarted) throw new TypeError('installed scheduler is already started');
    if (!this.installedRuntime || !this.installedAnchor || !this.runtimeAuthority?.sourceInspection) return;
    const isClosing = () => this.closeRequested || this.closed || this.released;
    if (isClosing()) return;
    await this.ownInstalledAdmission(async signal => {
      const { retireAbandonedWorkerPreparations } = await import('./preparing-successor.js');
      await retireAbandonedWorkerPreparations(this.driver, this.artifacts.withReadSignal(signal), this.owner,
        { store: this, selected: this.installedRuntime, anchor: this.installedAnchor, signal });
    });
    if (isClosing()) return;
    const recipe = await withHeldInstalledRuntime(this.installedRuntime, async installed => {
      await installed.revalidate();
      return { hasDiscovery: installed.modelAuthority !== undefined,
        hasBroker: installed.bundle.entries.some(entry => entry.entryId === MODEL_BROKER_ENTRY_ID &&
          entry.role === 'provider_adapter' && entry.executable) };
    });
    if (isClosing() || !recipe.hasBroker) return;
    await loadInstalledModelBroker(this.installedRuntime);
    if (isClosing()) return;
    this.installedAnchor.assertHeld(); assertActiveStateOwner(this.driver, this.owner);
    const rows = this.driver.prepare("SELECT id FROM runs WHERE status IN ('queued','running','waiting') ORDER BY created_at,id LIMIT ?")
      .all<{ id: string }>(INSTALLED_RUN_INVENTORY_LIMIT + 1);
    if (rows.length > INSTALLED_RUN_INVENTORY_LIMIT) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed scheduler retained inventory exceeds its bounded cut');
    for (const row of rows) {
      if (isClosing()) return;
      await this.retainInstalledAgent(row.id);
    }
    if (isClosing()) return;
    this.installedModelAdmissionReady = recipe.hasDiscovery;
    this.schedulerStarted = true;
    for (const row of rows) this.scheduleInstalledRun(row.id);
    this.armInstalledMaintenance();
  }

  private retainInstalledAgent(runId: string, material?: RunAssemblyValidationMaterial, admission?: Promise<AdmitRunResult | AdmitDeliveryResult>): Promise<InstalledContinuation> {
    const existing = this.installedAgents.get(runId); if (existing) return Promise.resolve(existing.agent);
    const loading = this.installedAgentLoads.get(runId); if (loading) return loading;
    const task = this.ownInstalledAdmission(async signal => {
      signal.throwIfAborted();
      if (admission && (await admission).run.id !== runId)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed admission deadline owner names a different Run');
      const run = readRun(this.driver, runId), spec = decodeRunSpec(await this.artifacts.withReadSignal(signal).readCanonical(run.specRef));
      // Read-only/preparation projections outlive initial loading for either
      // operation. Real received results retain their independent raw catalog
      // and original execution/broker owner through settlement and join.
      const readAbort = new AbortController();
      const readerSignal = AbortSignal.any([signal, readAbort.signal]);
      if (spec.operation === 'agent' && !material) {
        const { loadInstalledRunMaterial } = await import('./installed-run.js');
        material = await loadInstalledRunMaterial({ selected: this.installedRuntime!, artifacts: this.artifacts, assemblyRef: spec.assemblyRef, signal });
      }
      const agent = spec.operation === 'delivery'
        ? await loadDeliveryContinuation(this.driver, this.artifacts.withReadSignal(readerSignal), this.owner,
          { runId, releaseKeys: this.runtimeAuthority!.releaseKeys }, undefined, this.installedRuntime, readerSignal)
        : await loadAgentRun(this.driver, this.artifacts, this.owner,
          { runId, material: material!, releaseKeys: this.runtimeAuthority!.releaseKeys }, undefined, this.installedRuntime, signal,
          phase => { if (this.installedRunPhases.has(runId)) this.installedRunPhases.set(runId, phase); });
      signal.throwIfAborted();
      if (['queued', 'running', 'waiting'].includes(readRun(this.driver, runId).status)) this.installedAgents.set(runId, { agent, readAbort });
      return agent;
    });
    this.installedAgentLoads.set(runId, task);
    void task.then(() => this.installedAgentLoads.delete(runId), error => {
      if (!(error instanceof ResourceRetirementError)) this.installedAgentLoads.delete(runId);
    });
    return task;
  }

  /** One joined maintenance owner. The timer grants no authority: each action
   * uses the existing canonical-time, lease, stop and native resource gates. */
  private armInstalledMaintenance(): void {
    if (!this.supportsInstalledRuns() || this.installedMaintenanceTimer || this.installedMaintenance) return;
    this.installedMaintenanceTimer = setTimeout(() => {
      this.installedMaintenanceTimer = undefined;
      if (!this.supportsInstalledRuns()) return;
      const task = this.maintainInstalledRuns(); this.installedMaintenance = task;
      void task.then(() => {
        this.installedMaintenance = undefined; this.armInstalledMaintenance();
      }, error => {
        this.schedulerFailure ??= error;
        beginInstalledSchedulerDiagnostic('maintenance_global')?.failure(error, this.closeRequested);
        if (!(error instanceof ResourceRetirementError)) this.installedMaintenance = undefined;
      });
    }, 1000);
  }

  private async maintainInstalledRuns(): Promise<void> {
    let fence: TimeFenceAdvance | undefined;
    this.driver.transaction(connection => {
      assertActiveStateOwner(connection, this.owner);
      fence = advanceTimeFence(connection, this.owner.ownerEpoch, sampleCanonicalNow());
    });
    if (fence !== 'healthy') {
      // Timer progress is not clock authority. Regressed time revokes actual
      // external producers and workers; it never heals the fence or extends
      // deadlines, and the original StateOwner remains held.
      this.schedulerFailure ??= new KernelStorageError('RECOVERY_REQUIRED', 'installed maintenance canonical time fence refused progress');
      for (const task of this.sourceInspectionTasks) task.abort.abort();
      const joins = await Promise.allSettled([
        ...[...this.modelTransports.values()].map(transport => transport.close()),
        ...[...this.executions.values()].map(async opening => (await opening).close()),
      ]);
      const failure = joins.find(result => result.status === 'rejected');
      if (failure?.status === 'rejected') throw new ResourceRetirementError('clock-fenced installed resources did not close cleanly', failure.reason);
      throw this.schedulerFailure;
    }
    const rows = this.driver.prepare("SELECT id FROM runs WHERE status IN ('queued','running','waiting') ORDER BY created_at,id LIMIT ?")
      .all<{ id: string }>(INSTALLED_RUN_INVENTORY_LIMIT + 1);
    if (rows.length > INSTALLED_RUN_INVENTORY_LIMIT) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed maintenance inventory exceeds its bounded cut');
    for (const { id } of rows) {
      if (!this.supportsInstalledRuns()) return;
      try {
        let run = readRun(this.driver, id);
        if (!['queued', 'running', 'waiting'].includes(run.status)) continue;
        const agent = this.installedAgents.get(id)?.agent ?? await this.installedAgentLoads.get(id);
        if (!this.supportsInstalledRuns()) return;
        if (!agent) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run lacks its pre-scheduling deadline authority');
        run = readRun(this.driver, id);
        if (!['queued', 'running', 'waiting'].includes(run.status)) continue;
        if (sampleCanonicalNow() >= run.deadlineAt && !run.stopIntentRef) {
          run = (await agent.expireRun({ expectedRunRevision: run.revision })).run;
          this.requestInstalledRunStop(id);
        }
        if (!this.supportsInstalledRuns()) return;
        const opening = this.executions.get(id);
        if (opening && !run.stopIntentRef) {
          const scope = await opening;
          if (!this.supportsInstalledRuns()) return;
          const renewed = scope.execution.renewCurrentWorkerLease();
          if (renewed === 'expired') {
            run = readRun(this.driver, id);
            if (run.status === 'running' && run.activeWorkerLaunchId) {
              await beginWorkerRecovery(this.driver, this.artifacts, this.owner, { runId: id, expectedRunRevision: run.revision });
              await this.modelTransports.get(id)?.close();
            }
          }
        }
        run = readRun(this.driver, id);
        if (this.loadedExecutionScopes.get(id)?.execution.hasPendingCompletion() ||
            run.stopIntentRef || run.status === 'waiting' && run.waitingReason === 'reconciliation' ||
            run.status === 'queued' && !this.installedRunFailures.has(id)) this.scheduleInstalledRun(id);
        else if (run.status === 'running' && run.nextStep === 'agent' &&
            (this.installedModelCompletions.has(id) || this.installedModelClosures.has(id)) &&
            !this.installedRunTasks.has(id)) this.scheduleInstalledRun(id);
        else if (run.status === 'running' && run.nextStep === 'agent' && this.installedPreparationRetries.has(id) &&
            !this.installedRunTasks.has(id)) {
          if (agent.operation !== 'agent') throw new KernelStorageError('RECOVERY_REQUIRED', 'model retry does not belong to a delivery continuation');
          const attempt = await agent.readModelAttempt(this.installedAgents.get(id)?.readAbort?.signal);
          if (this.matchesInstalledPreparationRetry(id, attempt) && this.installedModelProgress(attempt) === 'retry')
            this.scheduleInstalledRun(id);
        }
      } catch (error) {
        if (error instanceof ResourceRetirementError) throw error;
        // A changing Run cut is not permission to weaken the native gate or
        // renew an expired lease. Preserve the refusal for health diagnostics.
        this.installedRunFailures.set(id, error);
        const diagnosis = beginInstalledSchedulerDiagnostic('maintenance');
        diagnosis?.phase(this.installedRunPhases.get(id));
        diagnosis?.failure(error, this.closeRequested);
      }
    }
  }

  private installedModelProgress(attempt: Awaited<ReturnType<AgentRunState['readModelAttempt']>>) {
    if (!attempt) return selectInstalledModelProgress(undefined);
    const entries = readInvocationAttempt(this.driver, attempt.run.id, attempt.entry.opId, attempt.entry.attempt);
    // The asynchronous closure reader does not freeze SQL. A changed cut is
    // retained until its actual current owner observes it again, never resent.
    if (entries.length === 0 || canonicalSha256(readRun(this.driver, attempt.run.id)) !== canonicalSha256(attempt.run) ||
        canonicalSha256(entries[0]) !== canonicalSha256(attempt.entry) ||
        canonicalSha256(entries.at(-1)) !== canonicalSha256(attempt.state)) return 'retain' as const;
    return selectInstalledModelProgress({ phase: attempt.state.phase, disposition: attempt.disposition,
      hasDispatchClaim: entries.some(entry => entry.phase === 'dispatch_claimed'),
      hasSettlement: attempt.state.budgetSettlementRef !== undefined, retry: attempt.retry.kind });
  }

  private matchesInstalledPreparationRetry(runId: string, attempt: Awaited<ReturnType<AgentRunState['readModelAttempt']>>): boolean {
    const hint = this.installedPreparationRetries.get(runId);
    if (!hint || !attempt || this.installedRunFailures.get(runId) !== hint.error || attempt.run.id !== runId ||
        attempt.run.status !== 'running' || attempt.run.stopIntentRef || !attempt.run.activeWorkerLaunchId ||
        attempt.entry.opId !== hint.opId || attempt.entry.attempt !== hint.attempt || attempt.entry.seq !== hint.preparedSeq ||
        attempt.entry.requestRef !== hint.requestRef || attempt.state.phase !== 'failed' || attempt.state.seq !== hint.failedSeq ||
        attempt.state.budgetSettlementRef !== hint.settlementRef) return false;
    const entries = readInvocationAttempt(this.driver, runId, hint.opId, hint.attempt);
    return entries.length === 2 && entries[0]?.phase === 'prepared' && entries[1]?.phase === 'failed' &&
      canonicalSha256(entries[0]) === canonicalSha256(attempt.entry) && canonicalSha256(entries[1]) === canonicalSha256(attempt.state);
  }

  private installedWorkerSlotAvailable(runId: string): boolean {
    // Serial JavaScript tasks do not bound retained workers. An unresolved
    // original launch keeps the one slot until its actual retirement commits.
    return !this.driver.prepare("SELECT 1 FROM worker_launches WHERE run_id != ? AND phase != 'retired' LIMIT 1").get(runId);
  }

  /** The driver owns this complete read, including before an execution scope
   * has opened. Store shutdown cancels and joins it through the same existing
   * read/admission producer scope; retained data grants no release authority. */
  private readInstalledPublicationCut(runId: string) {
    if (this.closed || this.closeRequested || this.released)
      return Promise.reject(new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed'));
    return this.ownInstalledAdmission(async signal => {
      const reads = this.artifacts.withReadSignal(signal);
      const { cut, prefix: publication } = await readDeliveryPublicationClosure(this.driver, reads, runId);
      const prefix = cut.journal.some(entry => entry.opKind === 'publish' && entry.phase === 'dispatch_claimed')
        ? publication : undefined;
      signal.throwIfAborted();
      return { cut, prefix };
    });
  }

  private requestInstalledRunStop(runId: string): void {
    const failed = (error: unknown) => {
      this.installedRunFailures.set(runId, error);
      const diagnosis = beginInstalledSchedulerDiagnostic('stop');
      diagnosis?.phase(this.installedRunPhases.get(runId));
      diagnosis?.failure(error, this.closeRequested);
      if (error instanceof ResourceRetirementError) this.schedulerFailure ??= error;
    };
    // Enter each already-loaded native owner synchronously after StopIntent.
    // The owners retain their joins; acknowledgement is not a cleanup receipt.
    try {
      const scope = this.loadedExecutionScopes.get(runId);
      const stopping = scope ? scope.execution.requestStop() : this.executions.get(runId)?.then(opened => opened.execution.requestStop());
      void stopping?.catch(failed);
    } catch (error) { failed(error); }
    try { void this.modelTransports.get(runId)?.close().catch(failed); }
    catch (error) { failed(error); }
  }

  private scheduleInstalledRun(runId: string): void {
    if (!this.supportsInstalledRuns() || this.installedRunTasks.has(runId)) return;
    const diagnosis = beginInstalledSchedulerDiagnostic('drive');
    this.installedRunPhases.set(runId, 'scheduled');
    const task = this.installedQueue.then(async () => {
      try { await this.driveInstalledRun(runId); }
      finally {
        try { await this.retireInstalledTerminalRun(runId); }
        finally {
          diagnosis?.phase(this.installedRunPhases.get(runId));
          this.installedRunPhases.delete(runId);
        }
      }
    });
    this.installedRunTasks.set(runId, task);
    this.installedQueue = task.catch(error => {
      this.installedRunFailures.set(runId, error);
      diagnosis?.failure(error, this.closeRequested);
      // One Run's ordinary provider refusal is not a failed physical lane.
      // Uncertain native retirement is process-wide and must stop admission.
      if (error instanceof ResourceRetirementError) this.schedulerFailure ??= error;
    });
    void task.then(() => this.installedRunTasks.delete(runId), error => {
      if (!(error instanceof ResourceRetirementError)) this.installedRunTasks.delete(runId);
    });
  }

  private async retireInstalledTerminalRun(runId: string): Promise<void> {
    if (this.closed || this.closeRequested || this.released) return;
    const run = readRun(this.driver, runId);
    if (!['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status)) return;
    // A model end is not terminal. Validate the actual terminal graph before
    // releasing its original installation/launcher image owners; failures keep
    // both the cache and StateOwner, never masquerading as positive cleanup.
    this.installedRunPhases.set(runId, 'terminal_retirement');
    await this.ownInstalledAdmission(signal => readRecoveryClosure(this.driver, this.artifacts.withReadSignal(signal), runId,
      phase => {
        if (this.installedRunPhases.has(runId)) this.installedRunPhases.set(runId, `result_recovery_${phase}`);
      }));
    const opening = this.executions.get(runId);
    if (opening) {
      try { await (await opening).close(); }
      catch (error) { throw error instanceof ResourceRetirementError ? error :
        new ResourceRetirementError('terminal Run launcher did not retire', error); }
      if (this.executions.get(runId) === opening) this.executions.delete(runId);
      this.loadedExecutionScopes.delete(runId);
    }
    this.installedAgents.get(runId)?.readAbort?.abort(new KernelStorageError('LEASE_FENCED', 'terminal Run reader is retired'));
    this.installedAgents.delete(runId);
    this.installedRunFailures.delete(runId);
    this.installedPreparationRetries.delete(runId);
  }

  private async driveInstalledRun(runId: string): Promise<void> {
    if (!this.supportsInstalledRuns()) return;
    const { loadInstalledRunMaterial } = await import('./installed-run.js');
    let run = readRun(this.driver, runId);
    if (!['queued', 'running', 'waiting'].includes(run.status)) return;
    this.installedRunPhases.set(runId, 'drive_agent');
    // Join the exact pre-registered load inside the one driver queue. This
    // observes its original failures even when the worker-slot gate will wait.
    // Deadline control precedes material/native/productive work.
    const agent = await this.retainInstalledAgent(runId);
    if (!this.supportsInstalledRuns()) return;
    run = readRun(this.driver, runId);
    if (!['queued', 'running', 'waiting'].includes(run.status)) return;
    // A fresh productive Run does not own a launcher while another original
    // launch retains the slot. Any resource history, cached owner or stop must
    // still enter the existing recovery/retirement path before this slot gate.
    if (run.status === 'queued' && run.nextStep === 'agent' && !run.cancelRequested && !run.stopIntentRef &&
        !run.activeWorkerLaunchId && !this.executions.has(runId) &&
        !this.driver.prepare('SELECT 1 FROM workspace_generations WHERE run_id = ? LIMIT 1').get(runId) &&
        !this.driver.prepare('SELECT 1 FROM worker_launches WHERE run_id = ? LIMIT 1').get(runId) &&
        !this.installedWorkerSlotAvailable(runId)) return;
    this.installedRunPhases.set(runId, 'drive_material');
    const readSignal = this.installedAgents.get(runId)?.readAbort?.signal;
    if (!readSignal) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed driver has no retained read owner');
    const reads = this.artifacts.withReadSignal(readSignal);
    reads.assertReadActive();
    const spec = decodeRunSpec(await reads.readCanonical(run.specRef));
    const material = spec.operation === 'agent'
      ? await loadInstalledRunMaterial({ selected: this.installedRuntime!, artifacts: reads, assemblyRef: spec.assemblyRef, signal: readSignal }) : undefined;
    const opening = this.executions.get(runId);
    let execution = opening ? (await opening).execution : undefined;
    const nativeExecution = async () => execution ??= await this.loadRunExecution(spec.operation === 'delivery'
      ? { runId, operation: 'delivery' } : { runId, material: material! });
    this.installedRunPhases.set(runId, 'drive_agent');
    let predecessorWorker = !opening && run.status === 'running' && run.activeWorkerLaunchId !== undefined;
    for (;;) {
      if (!this.supportsInstalledRuns()) return;
      let current = readRun(this.driver, runId);
      if (!['queued', 'running', 'waiting'].includes(current.status)) return;
      // An acknowledged user probe still owns its original background work.
      // Maintenance observes it, never competes for a second execution task.
      if (execution?.hasPendingOperation()) return;
      if (execution?.hasPendingCompletion()) {
        const failure = this.installedRunFailures.get(runId);
        const completingFailure = execution.hasPendingCompletion(failure);
        await execution.resumeCurrentCompletion({ expectedRunRevision: current.revision });
        if (completingFailure && this.installedRunFailures.get(runId) === failure) this.installedRunFailures.delete(runId);
        continue;
      }
      if (this.installedModelClosures.has(runId)) {
        await this.settleInstalledModelClosure(runId);
        continue;
      }
      if (this.installedModelCompletions.has(runId)) {
        if (agent.operation !== 'agent') throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery cannot own a model completion');
        await this.settleInstalledModelCompletion(runId, agent);
        continue;
      }
      if (predecessorWorker && current.status === 'running' && current.activeWorkerLaunchId) {
        predecessorWorker = false;
        current = await (await nativeExecution()).recoverWorker({ expectedRunRevision: current.revision });
      }
      if (current.status === 'waiting' && current.waitingReason === 'reconciliation' && current.waitingOnRef) {
        const wait = await reads.readCanonical<{ subject?: { kind?: string } }>(current.waitingOnRef);
        if (wait.subject?.kind === 'worker_death')
          current = await (await nativeExecution()).recoverWorker({ expectedRunRevision: current.revision });
        else if (wait.subject?.kind === 'publication_path' && agent.operation === 'delivery')
          current = await (await nativeExecution()).reconcilePublication({ expectedRunRevision: current.revision });
        else return;
      }
      if (current.status === 'waiting') return;
      if (current.status === 'queued' && (execution || this.driver.prepare(
        "SELECT 1 FROM workspace_generations WHERE run_id = ? AND phase = 'quarantined' LIMIT 1").get(runId))) {
        this.installedRunPhases.set(runId, 'drive_retirement');
        current = await (await nativeExecution()).resumeCurrentRetirement({ expectedRunRevision: current.revision });
        this.installedRunPhases.set(runId, 'drive_agent');
      }
      if (sampleCanonicalNow() >= current.deadlineAt && !current.stopIntentRef) {
        current = (await agent.expireRun({ expectedRunRevision: current.revision })).run;
        this.requestInstalledRunStop(runId);
      }
      if (current.nextStep === 'verify' && (current.cancelRequested || current.stopIntentRef)) {
        const cut = await readRecoveryClosure(this.driver, reads, runId);
        const progress = await readVerifierProgress(this.driver, reads, cut);
        if (cut.run.revision !== current.revision || readRun(this.driver, runId).revision !== current.revision) continue;
        // A positively retained integrity observation outranks a prior cancel
        // or deadline. It is derived again by the normal stop reducer.
        if (progress.entries.some(entry => entry.receipt?.outcome === 'source_mutation'))
          current = (await agent.stopForVerification({ expectedRunRevision: current.revision })).run;
      }
      if (current.cancelRequested || current.stopIntentRef) {
        if (agent.operation === 'delivery') {
          const { cut, prefix } = await this.readInstalledPublicationCut(runId);
          if (cut.run.revision !== current.revision || readRun(this.driver, runId).revision !== current.revision) continue;
          if (prefix) {
            if (readRun(this.driver, runId).revision !== current.revision) continue;
            const received = prefix.forward.at(-1);
            if (received?.pendingReceivedHandoff) {
              // The original effect and M retirement are already durable.
              // Consume only its genuine read-only result task before normal
              // Stop maintenance; never wait for or repeat a productive claim.
              await (await nativeExecution()).executeCurrentPublication({ expectedRunRevision: current.revision });
              continue;
            }
            if ([...prefix.entries.values()].some(entry => entry.claim && !entry.pendingReceivedHandoff &&
                (!entry.result || entry.result.item.outcome === 'unknown'))) {
              const scope = await nativeExecution();
              const updated = current.activeWorkerLaunchId
                ? await scope.recoverWorker({ expectedRunRevision: current.revision })
                : await scope.reconcilePublication({ expectedRunRevision: current.revision });
              if (updated.status === 'waiting') return;
              continue;
            }
            if (!prefix.authorization || prefix.forward.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
                prefix.abortResults.some(entry => !entry.result || entry.result.item.outcome === 'unknown')) return;
            if (readRun(this.driver, runId).revision !== current.revision) continue;
            if (prefix.abortResults.length < prefix.authorization.context.plan.abortOperations.length) {
              await (await nativeExecution()).executeCurrentPublicationMaintenance({ expectedRunRevision: current.revision });
              continue;
            }
            await (await nativeExecution()).finishCurrentStop({ expectedRunRevision: current.revision });
            return;
          }
        }
        if (execution || current.activeWorkerLaunchId) await (await nativeExecution()).finishCurrentStop({ expectedRunRevision: current.revision });
        else await agent.commitTerminalStop({ expectedRunRevision: current.revision });
        return;
      }
      if (current.nextStep === 'verify') {
        this.installedRunPhases.set(runId, 'drive_verify');
        const cut = await readRecoveryClosure(this.driver, reads, runId);
        let noOpDelivery = false;
        if (agent.operation === 'delivery') {
          const { readDeliveryVerificationMode } = await import('./run-result-recovery.js');
          const mode = await readDeliveryVerificationMode(this.driver, reads, cut);
          if (readRun(this.driver, runId).revision !== current.revision || cut.run.revision !== current.revision) continue;
          noOpDelivery = mode.noOp;
          if (mode.kind === 'inherited') {
            if (noOpDelivery) await (await nativeExecution()).executeCurrentNoOpDelivery({ expectedRunRevision: current.revision });
            else await agent.completeVerification({ expectedRunRevision: current.revision });
            continue;
          }
        }
        const progress = await readVerifierProgress(this.driver, reads, cut);
        if (readRun(this.driver, runId).revision !== current.revision || cut.run.revision !== current.revision) continue;
        const mutation = progress.entries.some(entry => entry.receipt?.outcome === 'source_mutation');
        const assertion = progress.entries.some(entry => entry.planEntry.required && entry.receipt?.outcome === 'assertion_failed');
        const exhaustedInfrastructure = progress.entries.some(entry => entry.planEntry.required && entry.receipt?.outcome === 'infra_failed' &&
          cut.journal.filter(row => row.opId === entry.terminalJournal?.opId && row.phase === 'dispatch_claimed').length >= entry.planEntry.maxAttempts);
        if (mutation || exhaustedInfrastructure || assertion && (agent.operation === 'delivery' || current.repairCount >= spec.budgets.repairAttempts)) {
          await agent.stopForVerification({ expectedRunRevision: current.revision });
          this.requestInstalledRunStop(runId); continue;
        }
        if (assertion) {
          if (agent.operation !== 'agent') throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery cannot authorize a model repair');
          await agent.authorizeVerifierRepair({ expectedRunRevision: current.revision }); continue;
        }
        // Empty and fully eligible plans need no worker. The result closure
        // accepts only its independently validated immutable receipts.
        if (progress.complete) {
          if (noOpDelivery) await (await nativeExecution()).executeCurrentNoOpDelivery({ expectedRunRevision: current.revision });
          else await agent.completeVerification({ expectedRunRevision: current.revision });
          continue;
        }
        const opId = verifierOperationId(runId, progress.candidate.itemId, progress.planRef, progress.nextVerifierIndex);
        const operation = cut.journal.filter(row => row.opId === opId), last = operation.at(-1);
        if (last && ['prepared', 'dispatch_claimed', 'unknown', 'abandoned'].includes(last.phase)) return;
        if (last?.phase === 'failed' && operation.some(row => row.attempt === last.attempt && row.phase === 'dispatch_claimed')) return;
        if (current.status === 'queued' && !this.installedWorkerSlotAvailable(runId)) return;
        await (await nativeExecution()).executeCurrentVerifier({ expectedRunRevision: current.revision }); continue;
      }
      // Final result transactions never borrow launcher images or compete for
      // a productive worker slot.
      if (current.nextStep === 'finalize') {
        this.installedRunPhases.set(runId, 'drive_finalize');
        await agent.commitRunResult({ expectedRunRevision: current.revision }); continue;
      }
      if (agent.operation === 'delivery') {
        if (current.nextStep !== 'delivery' || !current.frontierRef)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery cannot enter an agent or tool frontier');
        const frontier = await this.artifacts.readCanonical<import('../kernel/types.js').RunFrontier>(current.frontierRef);
        if (frontier.kind !== 'delivery') throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery requires its exact typed frontier');
        if (frontier.phase === 'merge') { await agent.mergeDelivery({ expectedRunRevision: current.revision }); continue; }
        if (frontier.phase === 'approval') { await agent.prepareDeliveryApproval({ expectedRunRevision: current.revision }); continue; }
        if (frontier.phase === 'publish') {
          const { cut, prefix } = await this.readInstalledPublicationCut(runId);
          if (cut.run.revision !== current.revision || readRun(this.driver, runId).revision !== current.revision) continue;
          if (prefix && [...prefix.entries.values()].some(entry => entry.claim && !entry.pendingReceivedHandoff &&
              (!entry.result || entry.result.item.outcome === 'unknown'))) {
            const scope = await nativeExecution();
            const updated = current.activeWorkerLaunchId
              ? await scope.recoverWorker({ expectedRunRevision: current.revision })
              : await scope.reconcilePublication({ expectedRunRevision: current.revision });
            if (updated.status === 'waiting') return;
            continue;
          }
          if (current.status === 'queued' && !this.installedWorkerSlotAvailable(runId)) {
            const received = prefix?.forward.at(-1);
            // A validated received handoff needs no new worker. All other
            // queued publication still obeys the original productive slot.
            if (!received?.pendingReceivedHandoff) return;
          }
          await (await nativeExecution()).executeCurrentPublication({ expectedRunRevision: current.revision }); continue;
        }
        // A structural frontier cannot replace original resource ownership.
        throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'delivery maintenance is not completely composed');
      }
      if (current.status === 'queued' && !this.installedWorkerSlotAvailable(runId)) return;
      if (current.nextStep === 'tool') {
        await (await nativeExecution()).executeCurrentTool({ expectedRunRevision: current.revision }); continue;
      }
      if (current.nextStep !== 'agent') return;
      const prior = await agent.readModelAttempt(readSignal);
      const progress = this.installedModelProgress(prior);
      if (progress === 'stop' && prior) {
        if (prior.prepared.request.kind === 'context_compaction') {
          await agent.stopForResourceFailure({ expectedRunRevision: prior.run.revision });
        } else {
          const inspector = supervisorInspectorIdentity(assertActiveStateOwner(this.driver, this.owner));
          const artifact = await this.artifacts.publishCanonical(inspector, inspector.format);
          await agent.stopForModelFailure({ expectedRunRevision: prior.run.revision,
            inspectorIdentityRef: artifact.ref, inspectorIdentityDigest: inspector.identityDigest });
        }
        this.requestInstalledRunStop(runId);
        continue;
      }
      // Permanent/unknown claims stay retained. A fresh
      // explicit/recovery drive may retry a validated free failure; only the
      // automatic maintenance wake additionally requires its original hint.
      if (progress === 'retain') return;
      const native = await nativeExecution();
      if (current.status === 'queued') {
        current = await native.activateCurrentWorker({ expectedRunRevision: current.revision });
      }
      if (progress === 'candidate') {
        await native.finishCurrentFinalTurn({ expectedRunRevision: current.revision }); continue;
      }
      let prepared: Awaited<ReturnType<AgentRunState['prepareModel']>>;
      try { prepared = await agent.prepareModel({ expectedRunRevision: current.revision, leaseEpoch: current.leaseEpoch }, readSignal); }
      catch (error) {
        if (!(error instanceof AgentContextExhaustedError)) throw error;
        // A typed planning refusal is not itself stop authority. Reproduce the
        // exact current retained cause before entering the ordinary proof-backed drain.
        await agent.stopForResourceFailure({ expectedRunRevision: current.revision });
        this.requestInstalledRunStop(runId);
        continue;
      }
      try { await this.dispatchInstalledModel(native, agent, prepared); }
      catch (error) {
        if (error instanceof ResourceRetirementError) throw error;
        const stopped = readRun(this.driver, runId);
        const entries = readInvocationAttempt(this.driver, runId, prepared.entry.opId, prepared.entry.attempt);
        if (stopped.stopIntentRef && entries.every(entry => entry.phase !== 'unknown') &&
          ['completed', 'failed'].includes(entries.at(-1)?.phase ?? '')) continue;
        throw error;
      }
    }
  }

  async cancelInstalledRun(request: unknown, identity: AuthenticatedControlIdentity) {
    if (!this.installedRuntime || !this.runtimeAuthority) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed Run composition is unavailable');
    const value = immutableSnapshot(request) as Record<string, unknown>;
    if (!value || !exactKeys(value, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'runId', 'expectedRevision']) ||
        value.protocolVersion !== 1 || value.method !== 'run.cancel') throw new KernelStorageError('INVALID_REQUEST', 'run.cancel requires its exact contract');
    const { requestDigest, ...core } = value;
    if (requestDigest !== canonicalSha256(core)) throw new KernelStorageError('INVALID_REQUEST', 'run.cancel request digest differs');
    await validateControlChannelClosure(this.artifacts, this.owner, identity);
    const runId = value.runId as string;
    let agent = this.installedAgents.get(runId)?.agent;
    if (!agent) {
      agent = await this.retainInstalledAgent(runId);
    }
    const result = await agent.cancelRun({ ...identity, requestId: value.requestId as string, expectedRunRevision: value.expectedRevision as number });
    // The StopIntent commits first; revocation enters native synchronously.
    this.requestInstalledRunStop(runId);
    this.scheduleInstalledRun(runId);
    return result;
  }

  get stateRootIdentity(): { ref: string; digest: string } {
    return {
      ref: this.owner.stateRootIdentityRef,
      digest: this.owner.stateRootIdentityDigest
    };
  }

  /** Only a successfully opened genuine installed Store owns this path. No
   * structural facade, supplied time callback or transferable fence result can
   * manufacture the two ordered database commits. */
  finalizeCredential(request: CredentialFinalizeRequest, identity: AuthenticatedControlIdentity): Promise<CredentialAuthorityOperationV1> {
    const heldOwner = installedCredentialFinalizers.get(this);
    if (!heldOwner) throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential finalization requires a genuine installed StateStore');
    if (!request || typeof request !== 'object' || Array.isArray(request) ||
        Reflect.ownKeys(request).length !== 6 || !['protocolVersion', 'method', 'requestId', 'operationId', 'attempt', 'commandDigest'].every(key => Object.hasOwn(request, key)) ||
        request.protocolVersion !== 1 || request.method !== 'credential.finalize' || typeof request.requestId !== 'string' ||
        typeof request.operationId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(request.operationId) ||
        typeof request.commandDigest !== 'string' || !/^[0-9a-f]{64}$/u.test(request.commandDigest) ||
        ![1, 2, 3].includes(request.attempt)) throw new KernelStorageError('INVALID_REQUEST', 'credential continuation metadata is invalid');
    assertRequestId(request.requestId);
    if (this.closed || this.closeRequested || this.released || heldOwner.retirementFailure)
      throw heldOwner.retirementFailure ?? new KernelStorageError('RECOVERY_REQUIRED', 'credential StateOwner is closing or closed');
    if (heldOwner.active) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential finalization is already active');
    heldOwner.active = true;
    const task = (async () => {
      await validateControlChannelClosure(this.artifacts, heldOwner.owner, identity);
      const platform = await loadInstalledCredentialPlatform(heldOwner.selected);
      return withCredentialAuthorityLock(heldOwner.selected, async token => {
        const held = checkedCredentialToken(token);
        ensureEndpointSchema(held.database!);
        if (credentialSchemaVersion(held.database!) !== 2 || heldOwner.owner.stateRootIdentityDigest !== held.rootIdentity.identityDigest ||
            heldOwner.owner.stateRootIdentityRef !== canonicalSha256(held.rootIdentity) || identity.principalId !== held.ownerPrincipalId)
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential finalization root/principal differs');
        const facts = readCredentialFacts(held, request.requestId), operation = facts.at(-1)?.operation;
        if (!operation || operation.operationId !== request.operationId || operation.attempt !== request.attempt || operation.requestDigest !== request.commandDigest)
          throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential continuation does not name its original operation');
        if (operation.phase === 'committed') {
          if (!readCredentialHistory(held, operation.credentialGrantId, operation.committedAuthorityRevision).result)
            throw new TypeError('credential committed replay result is absent');
          assertCurrentControlFrame(heldOwner.owner, identity); token.assertHeld();
          return immutableSnapshot(operation);
        }
        const expected = facts.at(-1)?.observation;
        if (operation.phase !== 'secret_stored' || !expected)
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential continuation is not secret_stored');
        const original = retainedCredentialChannel(held, operation);
        // Closing may have won while the genuine selection/scope opened.
        // A committed replay above does not need a new inspection or grant.
        if (this.closeRequested || this.closed || this.released)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'credential StateOwner is closing');
        const inspection = platform.secretService({ kind: 'inspect',
          selector: credentialSelector(held, operation), expectedObservation: expected });
        heldOwner.inspection = inspection;
        let fresh: SecretServiceObservation;
        try { fresh = decodeSecretServiceObservation(await inspection); }
        catch (error) {
          if (error instanceof ResourceRetirementError) heldOwner.retirementFailure ??= error;
          throw error;
        }
        finally {
          // The original credential scope must outlive native cancellation,
          // even when its observation refused. Never detach the native job or
          // release the database/guard while its timer/bus/worker may remain.
          try { if (heldOwner.inspectionJoin) await heldOwner.inspectionJoin; }
          catch (error) { heldOwner.retirementFailure ??= error instanceof ResourceRetirementError ? error :
            new ResourceRetirementError('credential inspection cancellation did not retire', error); }
          if (heldOwner.retirementFailure) throw heldOwner.retirementFailure;
          heldOwner.inspection = undefined; heldOwner.inspectionJoin = undefined;
        }
        const observationBody = (value: SecretServiceObservation) => {
          const { kind: _kind, observationDigest: _digest, ...body } = value; return body;
        };
        if (fresh.kind !== 'present' || !canonicalJsonBytes(observationBody(fresh)).equals(canonicalJsonBytes(observationBody(expected))))
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential platform owner/alias/item changed');
        token.assertHeld();
        const core = operation.commandCore, registration = credentialEndpoint(held, core);
        const endpoint = readEndpointHistory(held, registration.endpointRegistrationId).at(-1);
        const latest = readCredentialHistory(held, operation.credentialGrantId).latest;
        if (!endpoint || endpoint.state !== 'active' || endpoint.expectedRegistrationArtifactRef !== core.endpointRegistrationRef ||
            operation.intendedAuthorityRevision >= Number.MAX_SAFE_INTEGER ||
            operation.intendedAuthorityRevision !== (latest?.authorityRevision ?? 0) + 1 ||
            operation.intendedSecretGeneration !== (latest?.secretGeneration ?? 0) + 1 ||
            (core.kind === 'enroll' ? !!latest : !latest || latest.state !== 'active' || core.purpose !== latest.purpose ||
              core.endpointRegistrationRef !== latest.endpointRegistrationRef || core.endpointIdentityDigest !== latest.endpointIdentityDigest ||
              core.tlsPolicyDigest !== latest.tlsPolicyDigest))
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential endpoint or intended revision changed');
        // All async closure/platform work is finished. No await, externally
        // supplied callback, D-Bus or CAS operation occurs until readback.
        const cut = heldOwner.driver.transaction(connection => {
          if (this.closeRequested || this.closed || this.released) throw new KernelStorageError('RECOVERY_REQUIRED', 'credential StateOwner is closing');
          token.assertHeld();
          const frame = assertCurrentControlFrame(heldOwner.owner, identity), peer = frame.processIdentity;
          if (peer.platform !== original.processIdentity.platform || peer.ownerUid !== original.processIdentity.ownerUid ||
              peer.pid !== original.processIdentity.pid || peer.processStartToken !== original.processIdentity.processStartToken ||
              peer.executableImageDigest !== original.processIdentity.executableImageDigest)
            throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential continuation is not its original producer lifetime');
          const owner = assertActiveStateOwner(connection, heldOwner.owner);
          if (owner.runtimeBundleRef !== heldOwner.selected.bundleDigest || owner.runtimeBundleManifestDigest !== heldOwner.selected.bundle.manifestDigest)
            throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential StateOwner signed bundle changed');
          const now = sampleCanonicalNow();
          const status = advanceTimeFence(connection, owner.ownerEpoch, now);
          return { now, status, channelOpenedAt: frame.channel.openedAt };
        });
        // Regression survives this refusal: its transaction already committed.
        if (cut.status !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence refuses credential expansion');
        const nowMs = parseCanonicalTime(cut.now);
        if ([endpoint.createdAt, registration.createdAt, ...(latest ? [latest.createdAt] : []), operation.createdAt, core.externalSubject.observedAt,
          original.channel.openedAt, cut.channelOpenedAt].some(time => parseCanonicalTime(time) > nowMs))
          throw new CredentialFinalizationTimeError('noncausal_time');
        if (core.expiresAt && parseCanonicalTime(core.expiresAt) <= nowMs)
          throw new CredentialFinalizationTimeError('expired');
        return commitCredentialWrite(held, operation, cut.now);
      });
    })();
    const joined = task.catch(error => {
      if (error instanceof ResourceRetirementError) heldOwner.retirementFailure = error;
      throw error;
    }).finally(() => { heldOwner.active = false; heldOwner.task = undefined; });
    heldOwner.task = joined;
    return joined;
  }

  /** Signed owner observation, not an installation or execution-capacity claim. */
  async readSupervisorHello(identity: AuthenticatedControlIdentity): Promise<SupervisorHelloV1> {
    if (this.closed || this.closeRequested || this.released)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'StateStore is closing or closed');
    await validateControlChannelClosure(this.artifacts, this.owner, identity);
    const bundle = this.runtimeAuthority?.bundle;
    if (bundle === undefined)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'public Supervisor observation requires signed runtime authority');
    const completeRef = canonicalSha256(bundle);
    const observation = this.driver.readSnapshot(connection => {
      const owner = assertActiveStateOwner(connection, this.owner);
      if (owner.runtimeBundleRef !== completeRef || owner.runtimeBundleManifestDigest !== bundle.manifestDigest)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'Supervisor observation does not match its active signed owner');
      return { supervisorInstanceId: owner.supervisorInstanceId,
        activeRuntimeBundle: { schemaVersion: 1 as const, runtimeBundleRef: completeRef,
          bundleDigest: completeRef, bundleVersion: bundle.bundleVersion },
        headlessSchemaRange: bundle.headlessSchemaRange };
    });
    await validateControlChannelClosure(this.artifacts, this.owner, identity);
    assertActiveStateOwner(this.driver, this.owner);
    return immutableSnapshot(observation);
  }

  async readSupervisorStatus(identity: AuthenticatedControlIdentity): Promise<SupervisorStatusV1> {
    if (!this.installedRuntime || !this.runtimeAuthority)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'Supervisor status requires a held verified installation');
    if (this.closed || this.closeRequested || this.released)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'StateStore is closing or closed');
    const authenticated = { ...identity };
    // Preserve the entry and both root-binding full revalidations. Only their
    // fixed, authority-free observation is independent of business FIFO: a
    // model's credential callback may be awaiting this client's response.
    await readInstalledRuntimeObservation(this.installedRuntime);
    const installed = await readInstalledRuntimeObservation(this.installedRuntime);
    await assertInstalledObservedRootBinding(this.stateRoot, this.owner.filesystem, installed);
    await validateControlChannelClosure(this.artifacts, this.owner, authenticated);
    const cut = this.driver.readSnapshot(connection => {
      try {
        const owner = assertActiveStateOwner(connection, this.owner);
        if (owner.runtimeBundleRef !== installed.bundleDigest ||
            owner.runtimeBundleManifestDigest !== installed.manifestDigest)
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed inventory differs from the active signed owner');
        const counts = connection.prepare(`SELECT
          COALESCE(SUM(status = 'queued'), 0) AS queued,
          COALESCE(SUM(status = 'running'), 0) AS running,
          COALESCE(SUM(status IN ('queued', 'running', 'waiting')), 0) AS nonterminal
          FROM runs`).get<{ queued: unknown; running: unknown; nonterminal: unknown }>()!;
        const nonterminal = requiredSafeInteger(counts.nonterminal, 'nonterminal Run count');
        const pins = connection.prepare(`SELECT CASE WHEN length(CAST(spec_ref AS BLOB))=64 THEN spec_ref ELSE NULL END AS spec_ref
          FROM runs WHERE status IN ('queued','running','waiting') ORDER BY id LIMIT ?`).all<{ spec_ref: string }>(INSTALLED_RUN_INVENTORY_LIMIT + 1);
        if (pins.length !== nonterminal || pins.length > INSTALLED_RUN_INVENTORY_LIMIT)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'installed nonterminal pin inventory exceeds its bounded cut');
        for (const pin of pins) assertArtifactRef(pin.spec_ref);
        return { supervisorInstanceId: owner.supervisorInstanceId,
          stateSchemaVersion: readSchemaUserVersion(connection),
          queuedRuns: requiredSafeInteger(counts.queued, 'queued Run count'),
          runningRuns: requiredSafeInteger(counts.running, 'running Run count'), pins };
      } catch (cause) {
        if (cause instanceof TypeError || cause instanceof SyntaxError)
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained Supervisor status metadata is invalid', { cause });
        throw cause;
      }
    });
    let incompatiblePinnedRunCount = 0;
    for (const pin of cut.pins) {
      const spec = decodeRunSpec(await this.artifacts.readCanonical(pin.spec_ref));
      const assembly = (await import('../model/run-assembly.js')).decodeRetainedRunAssembly(await this.artifacts.readCanonical(spec.assemblyRef));
      if (assembly.runtime.runtimeBundleRef !== installed.bundleDigest ||
          assembly.runtime.runtimeBundleManifestDigest !== installed.manifestDigest) incompatiblePinnedRunCount++;
    }
    await assertInstalledObservedRootBinding(this.stateRoot, this.owner.filesystem,
      await readInstalledRuntimeObservation(this.installedRuntime));
    await validateControlChannelClosure(this.artifacts, this.owner, authenticated);
    assertActiveStateOwner(this.driver, this.owner);
    const summary = { schemaVersion: 1 as const, runtimeBundleRef: installed.bundleDigest,
      bundleDigest: installed.bundleDigest, bundleVersion: installed.bundleVersion };
    return immutableSnapshot({ method: 'supervisor.status' as const,
      health: this.closeRequested ? 'draining' as const : this.supportsInstalledRuns() && incompatiblePinnedRunCount === 0 && this.installedRunFailures.size === 0
        ? 'ready' as const : 'degraded' as const,
      supervisorInstanceId: cut.supervisorInstanceId,
      queue: { queuedRuns: cut.queuedRuns, runningRuns: cut.runningRuns, capacity: this.supportsInstalledRuns() ? 1 : 0 },
      stateSchemaVersion: cut.stateSchemaVersion, activeRuntimeBundle: summary,
      installedRuntimeBundles: [summary], incompatiblePinnedRunCount });
  }

  /** Internal authenticated transport, not an installed public protocol server. */
  openLocalControl(onConnection: (connection: LocalControlConnection) => void, onError: (error: Error) => void): LocalControlListener {
    if (this.closed || this.closing || this.released) throw new KernelStorageError('RECOVERY_REQUIRED', 'StateStore is closing or closed');
    assertActiveStateOwner(this.driver, this.owner);
    const nativeListener = openLocalControlListener(this.artifacts, this.owner, onConnection, onError);
    const listener: LocalControlListener = Object.freeze({ close: () => {
      const closing = nativeListener.close();
      void closing.then(() => this.controlListeners.delete(listener), () => {});
      return closing;
    } });
    this.controlListeners.add(listener);
    return listener;
  }

  static async open(stateRoot: string, runtimeAuthority?: StateStoreRuntimeAuthority,
    installedRuntime?: HeldInstalledRuntime, installedAnchor?: HeldInstalledAnchor): Promise<StateStore> {
    if (installedAnchor !== undefined) withInstalledWorkerRoot(installedRuntime!, installedAnchor, () => {});
    let opening: StateStore | undefined;
    try {
      const store = installedRuntime !== undefined
        ? await withHeldInstalledRuntime(installedRuntime, async installed => {
          // Own the constructed resources before the borrow joins its tracked
          // checks: that join can reject after openCore has returned.
          opening = await StateStore.openCore(stateRoot, runtimeAuthority, installed, installedRuntime, installedAnchor);
          return opening;
        }) : await StateStore.openCore(stateRoot, runtimeAuthority);
      opening = store;
      // Worker loaders enqueue on the same installed handle. Join the initial
      // borrow first, then retire old native resources before publishing Store.
      const authority = store.runtimeAuthority;
      await retireAbandonedPreactivations(store.driver, store.artifacts, store.owner,
        authority?.execution && { ...authority.execution,
          runtimeAuthority: { bundle: authority.bundle, releaseKeys: authority.releaseKeys } },
        store.installedRuntime, store.installedAnchor);
      if (store.installedRuntime) installedCredentialFinalizers.set(store, { driver: store.driver,
        owner: store.owner, selected: store.installedRuntime, active: false });
      return store;
    } catch (error) {
      if (opening !== undefined) {
        // A rejected borrow has not established retirement of retained native
        // resources. Validation failure is not permission to release the flock.
        failStateStoreOpening(opening.owner.filesystem, opening.driver,
          error instanceof ResourceRetirementError ? error
            : new ResourceRetirementError('StateStore opening validation did not complete retirement', error));
      }
      throw error; // openCore already owns cleanup when no Store was constructed.
    }
  }

  private static async openCore(stateRoot: string, runtimeAuthority?: StateStoreRuntimeAuthority,
    installed?: InstalledRuntimeBorrow, installedRuntime?: HeldInstalledRuntime,
    installedAnchor?: HeldInstalledAnchor): Promise<StateStore> {
    runtimeAuthority = runtimeAuthority === undefined ? undefined : immutableSnapshot(runtimeAuthority);
    if (process.platform !== 'darwin' && process.platform !== 'linux') {
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', `state store is unsupported on ${process.platform}`);
    }
    if (runtimeAuthority) {
      verifyRuntimeBundle(runtimeAuthority.bundle, runtimeAuthority.releaseKeys);
    }
    if (installed && (stateRoot !== installed.stateRoot.canonicalPath || runtimeAuthority === undefined ||
        canonicalSha256(runtimeAuthority.bundle) !== installed.bundleDigest ||
        runtimeAuthority.bundle.manifestDigest !== installed.bundle.manifestDigest)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateStore requires the exact held installed root and signed bundle');
    }
    const native = installed ? await installed.loadStateOwner() : await loadNativeStateOwner(runtimeAuthority?.bundle);
    if (runtimeAuthority) {
      const supervisor = runtimeAuthority.bundle.entries.find((entry) => entry.role === 'supervisor')!;
      if (supervisor.digest !== (await native.observeCurrentProcess()).executableImageDigest ||
          runtimeAuthority.bundle.stateSchemaRange.min > KERNEL_STATE_SCHEMA_VERSION ||
          runtimeAuthority.bundle.stateSchemaRange.max < KERNEL_STATE_SCHEMA_VERSION) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'signed Supervisor does not match this process or state schema');
      }
    }
    await assertPrivateStateRoot(stateRoot);
    const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
    const databasePath = path.join(stateRoot, KERNEL_DATABASE_FILENAME);
    const databaseExists = await lstat(databasePath).then(() => true, (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return false;
      throw error;
    });
    let heldLock: HeldStateOwnerLock;
    try {
      // An existing database must never silently recreate a missing lock inode.
      heldLock = Object.freeze(native.acquireLock(stateRoot, !databaseExists));
    } catch (error) {
      throw new KernelStorageError('RECOVERY_REQUIRED', error instanceof Error ? error.message : 'StateOwner OS lock acquisition failed');
    }
    let driver: SqliteDriver | undefined;
    try {
      assertStateOwnerLock(heldLock);
      if (installed) await assertInstalledRootBinding(stateRoot, heldLock, installed);
      driver = openSqliteDriver(databasePath);
      const preflightSchemaVersion = readSchemaUserVersion(driver);
      if (preflightSchemaVersion === 1) {
        const priorOwners = driver
          .prepare('SELECT count(*) AS count FROM state_owners')
          .get<{ count: unknown }>();
        if (Number(priorOwners?.count ?? 0) !== 0) {
          throw new KernelStorageError(
            'RECOVERY_REQUIRED',
            'schema-v1 authority requires the explicit WP01 generation migration path'
          );
        }
      }
      applyKernelSchema(driver);
      const ownerHistory = driver
        .prepare('SELECT count(*) AS count FROM state_owners')
        .get<{ count: unknown }>();
      const allowLayoutCreation = Number(ownerHistory?.count ?? 0) === 0;
      await ensurePrivateDirectory(casRoot, allowLayoutCreation);
      const artifacts = new ArtifactCatalog(new ContentAddressedStore(casRoot));
      const owner = await acquireOrBootstrapStateOwner(stateRoot, driver, artifacts, native, heldLock, runtimeAuthority?.bundle, installed);
      const ownerContext = await stateOwnerContextFromArtifacts(stateRoot, artifacts, owner, heldLock);
      // Close abandoned capture resources before publishing the successor
      // Store. Retained reservations replace neither source nor client: only
      // actual authenticated replay later binds the immutable error response.
      const { retireAbandonedSourceInspections } = await import('./source-inspection-owner.js');
      await retireAbandonedSourceInspections(driver, artifacts, ownerContext,
        runtimeAuthority?.sourceInspection && { bundle: runtimeAuthority.bundle,
          releaseKeys: runtimeAuthority.releaseKeys, sandboxProfile: runtimeAuthority.sourceInspection.sandboxProfile },
        installedRuntime && installedAnchor ? { runtime: installedRuntime, anchor: installedAnchor } : undefined);
      const { validateAuthorizationHistory } = await import('./authorization.js');
      await validateAuthorizationHistory(driver, artifacts, ownerContext, runtimeAuthority);
      return new StateStore(stateRoot, driver, artifacts, ownerContext, runtimeAuthority, installedRuntime, installedAnchor);
    } catch (error) {
      failStateStoreOpening(heldLock, driver, error);
    }
  }

  createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    return createSession(this.driver, this.artifacts, this.owner, input);
  }

  admitRun(input: AdmitRunInput): Promise<AdmitRunResult> {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return this.ownInstalledAdmission(signal => admitRun(this.driver, this.artifacts, this.owner, input, this.runtimeAuthority, signal));
  }

  registerWorkspaceGeneration(input: RegisterWorkspaceGenerationInput) {
    return registerWorkspaceGeneration(this.driver, this.artifacts, this.owner, input);
  }

  recordWorkspaceGenerationPreactivated(input: RecordWorkspaceGenerationPreactivatedInput) {
    return recordWorkspaceGenerationPreactivated(this.driver, this.artifacts, this.owner, input);
  }

  reserveWorkerLaunch(input: ReserveWorkerLaunchInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return reserveWorkerLaunch(this.driver, this.artifacts, this.owner, input);
  }

  recordWorkerPreactivated(input: RecordWorkerPreactivatedInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return recordWorkerPreactivated(this.driver, this.artifacts, this.owner, input);
  }

  activateWorkerLease(input: ActivateWorkerLeaseInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return activateWorkerLease(this.driver, this.owner, input);
  }

  renewWorkerLease(input: RenewWorkerLeaseInput) {
    return renewWorkerLease(this.driver, this.owner, input);
  }

  beginGenerationRevocation(input: BeginGenerationRevocationInput) {
    return beginGenerationRevocation(this.driver, this.owner, input);
  }

  beginGenerationCheckpoint(input: BeginGenerationCheckpointInput) {
    return beginGenerationCheckpoint(this.driver, this.owner, input);
  }

  sealWorkerGeneration(input: SealWorkerGenerationInput) {
    return sealWorkerGeneration(this.driver, this.artifacts, this.owner, input);
  }

  prepareInvocation(input: PrepareInvocationInput) {
    return prepareInvocation(this.driver, this.artifacts, this.owner, input);
  }

  loadAgentRun(input: LoadAgentRunInput) {
    return this.ownInstalledAdmission(signal => loadAgentRun(this.driver, this.artifacts, this.owner, input, undefined, this.installedRuntime, signal));
  }

  /** Production broker only. The native image owns raw credential/header bytes
   * and transport resources; SQL owns every claim, budget and continuation. */
  private dispatchInstalledModel(execution: RunExecution, agent: AgentRunState,
    attempt: Awaited<ReturnType<AgentRunState['prepareModel']>>) {
    const runId = attempt.entry.runId;
    if (this.modelOperations.has(runId)) throw new KernelStorageError('REVISION_CONFLICT', 'Run already owns a native model operation');
    const operation = this.dispatchInstalledModelOwned(execution, agent, attempt);
    this.modelOperations.set(runId, operation);
    const release = (error?: unknown) => { if (!(error instanceof ResourceRetirementError)) this.modelOperations.delete(runId); };
    void operation.then(() => release(), release); return operation;
  }

  private async settleInstalledModelClosure(runId: string) {
    const observation = this.installedModelClosures.get(runId);
    if (!observation || !this.installedRuntime)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'model failure lost its original joined transport owner');
    const { prepared, claimed, transport, initial } = observation;
    // Closing is authority reducing. Retain its owner before this join or
    // any SQL/token read can fail; failure cannot fall back to disposal.
    const closure = observation.closure ??= await transport.close();
    const active = assertActiveStateOwner(this.driver, this.owner);
    const entries = readInvocationAttempt(this.driver, runId, prepared.opId, prepared.attempt);
    if (active.supervisorInstanceId !== claimed.supervisorInstanceId || active.ownerEpoch !== claimed.stateOwnerEpoch ||
        entries.length !== 2 || canonicalSha256(entries[0]) !== canonicalSha256(prepared) ||
        canonicalSha256(entries[1]) !== canonicalSha256(claimed))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'model failure no longer owns its exact permanent claim');
    if (!closure.networkStarted) {
      const { failInstalledModelClaimWithoutRelease } = await import('./broker-no-release.js');
      await failInstalledModelClaimWithoutRelease(this.driver, this.artifacts, this.owner, this.installedRuntime,
        { transport, prepared, claim: claimed });
    } else {
      const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await this.artifacts.publishCanonical(inspector, inspector.format);
      const evidence: BrokerInvocationAmbiguityEvidenceV1 = { schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1',
        runId, frontierRef: initial.authority.grant.frontierRef, frontierDigest: initial.authority.grant.frontierRef,
        opId: claimed.opId, opKind: 'model', attempt: claimed.attempt, dispatchId: claimed.dispatchId!, dispatchJournalSeq: claimed.seq,
        operationRequestRef: claimed.requestRef, operationRequestDigest: initial.request.requestDigest,
        operationTargetRef: initial.authority.targetRef, operationTargetDigest: initial.authority.targetDigest,
        claimingSupervisorInstanceId: claimed.supervisorInstanceId!, claimingStateOwnerEpoch: claimed.stateOwnerEpoch!,
        inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
        observedAt: sampleCanonicalNow(), evidenceDigest: '', ambiguityKind: 'broker_channel_lost_after_claim',
        brokerFenceTokenDigest: claimed.brokerFenceTokenDigest!, failureCode: closure.requestStarted
          ? 'response_stream_interrupted' : 'connection_lost_after_release_possible', durableTerminalResultAbsent: true };
      evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(evidence);
      const artifact = await this.artifacts.publishCanonical(evidence, evidence.format);
      // This is the original genuine closed producer, not permission to
      // repeat network I/O. Every released outcome remains fully charged.
      await markInstalledBrokerAmbiguity(this.driver, this.artifacts, this.owner, {
        runId, opId: prepared.opId, attempt: prepared.attempt, expectedRunRevision: readRun(this.driver, runId).revision,
        evidenceRef: artifact.ref, evidenceDigest: evidence.evidenceDigest });
    }
    transport.releaseDispatchFence();
    if (this.installedModelClosures.get(runId) === observation) this.installedModelClosures.delete(runId);
    if (this.modelTransports.get(runId) === transport) this.modelTransports.delete(runId);
  }

  private async settleInstalledModelCompletion(runId: string, agent: AgentRunState) {
    const observation = this.installedModelCompletions.get(runId);
    if (!observation) throw new KernelStorageError('RECOVERY_REQUIRED', 'received model result lost its original settlement owner');
    const active = assertActiveStateOwner(this.driver, this.owner);
    const entries = readInvocationAttempt(this.driver, runId, observation.prepared.opId, observation.prepared.attempt);
    if (active.supervisorInstanceId !== observation.claimed.supervisorInstanceId || active.ownerEpoch !== observation.claimed.stateOwnerEpoch ||
        entries.length !== 2 || canonicalSha256(entries[0]) !== canonicalSha256(observation.prepared) ||
        canonicalSha256(entries[1]) !== canonicalSha256(observation.claimed)) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'received model result no longer owns its exact original claim');
    }
    const completed = await agent.completeModel({ opId: observation.prepared.opId, attempt: observation.prepared.attempt,
      expectedRunRevision: readRun(this.driver, runId).revision, result: observation.result });
    if (this.installedModelCompletions.get(runId) === observation) this.installedModelCompletions.delete(runId);
    const retry = this.installedPreparationRetries.get(runId);
    if (retry && retry.opId === observation.prepared.opId && retry.attempt < observation.prepared.attempt &&
        retry.failedSeq < observation.prepared.seq && this.installedRunFailures.get(runId) === retry.error) {
      this.installedPreparationRetries.delete(runId); this.installedRunFailures.delete(runId);
    }
    return completed;
  }

  private async dispatchInstalledModelOwned(execution: RunExecution, agent: AgentRunState,
    attempt: Awaited<ReturnType<AgentRunState['prepareModel']>>) {
    const selected = this.installedRuntime;
    if (!selected || !this.runtimeAuthority || !this.installedAnchor)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed broker composition is unavailable');
    const broker = await loadInstalledModelBroker(selected);
    const prepared = attempt.entry, runId = prepared.runId;
    const initial = await readModelClaimCut(this.driver, this.artifacts, prepared);
    if (initial.assembly.provider.name !== 'openai-compatible' || initial.authority.target.format !== 'cliq-endpoint-registration-v1' ||
        attempt.prepared.outbound.requestPath !== '/chat/completions')
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'model request does not select the exact installed broker recipe');
    const target = initial.authority.target;
    const frozen = await this.artifacts.mapReads(initial.assembly.provider.credentialGrantRefs, async ref =>
      decodeEndpointCredentialGrantBinding(await this.artifacts.readCanonical(ref)));
    const trustStoreBytes = await this.artifacts.readBytes(target.tls.trustStoreRef);
    const failPreparation = async (retryError?: KernelStorageError | CredentialScopeBusyError, retainedErrorRef?: string) => {
      const input = { runId, opId: prepared.opId, attempt: prepared.attempt, expectedRunRevision: readRun(this.driver, runId).revision };
      const evidence = { schemaVersion: 1, format: 'cliq-invocation-error-v1', runId, opId: prepared.opId, attempt: prepared.attempt,
        requestRef: prepared.requestRef, reason: 'installed_model_preparation_refused', observedAt: sampleCanonicalNow() };
      const errorRef = retainedErrorRef ?? (await this.artifacts.publishCanonical(evidence, evidence.format)).ref;
      const failed = await failInvocationBeforeDispatch(this.driver, this.artifacts, this.owner, { ...input, errorRef });
      if (retryError) {
        const current = await agent.readModelAttempt();
        const entries = readInvocationAttempt(this.driver, runId, prepared.opId, prepared.attempt);
        if (current && current.run.status === 'running' && !current.run.stopIntentRef && current.run.activeWorkerLaunchId &&
            canonicalSha256(current.entry) === canonicalSha256(prepared) && canonicalSha256(current.state) === canonicalSha256(failed.entry) &&
            entries.length === 2 && entries[0]?.phase === 'prepared' && entries[1]?.phase === 'failed' &&
            canonicalSha256(entries[0]) === canonicalSha256(prepared) && canonicalSha256(entries[1]) === canonicalSha256(failed.entry) &&
            this.installedModelProgress(current) === 'retry') {
          this.installedPreparationRetries.set(runId, { error: retryError, opId: prepared.opId, attempt: prepared.attempt,
            preparedSeq: prepared.seq, failedSeq: failed.entry.seq, requestRef: prepared.requestRef, settlementRef: failed.entry.budgetSettlementRef! });
        }
      }
    };
    let callbackEntered = false;
    const dispatch = async (token: HeldCredentialAuthorityLock) => {
      callbackEntered = true;
      const held = checkedCredentialToken(token);
      let transport: NativeModelTransport | undefined;
      let fenceRetained = false;
      let claimed: import('../kernel/types.js').InvocationJournalEntry | undefined;
      let receivedResponse = false;
      let preparationError: KernelStorageError | undefined;
      try {
        const authority = currentModelAuthority(held, initial.authority.principalId, target.endpointRegistrationId,
          frozen.map(binding => binding.credentialGrantId), sampleCanonicalNow(), { endpoint: target, bindings: frozen });
        try {
          if (this.closeRequested || this.closed || this.released) throw new KernelStorageError('LEASE_FENCED', 'model broker is closing');
          transport = broker.prepareModelTransport({ provider: 'openai-compatible', selector: authority.selector,
            expectedObservation: authority.observation, target: { hostAscii: target.target.hostAscii, port: target.target.port,
              basePath: target.target.basePath, serverNameAscii: target.tls.serverNameAscii, spkiSha256Pins: target.tls.spkiSha256Pins },
            trustStoreBytes, trustStoreDigest: target.tls.trustStoreRef, requestPath: '/chat/completions',
            bodyBytes, bodyBytesDigest: initial.request.bodyBytesRef });
          // No await between acquiring and registering the real owner: stop,
          // expiry and shutdown can revoke even an in-flight local redemption.
          this.modelTransports.set(runId, transport);
          await transport.ready;
        } catch (error) {
          // Only this original, joined native preparation failure can wake
          // another free attempt. Authority, claim and cleanup failures cannot.
          if (error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED' &&
              !(error instanceof ResourceRetirementError) && !(error instanceof InstalledModelAuthorizationError)) preparationError = error;
          throw error;
        }
        if (this.closeRequested || this.closed) throw new KernelStorageError('LEASE_FENCED', 'model broker is closing');
        token.assertHeld();
        // Retain the real original token/mutex before a permanent SQL claim.
        // Transport close still joins I/O immediately, but cannot destroy the
        // sole live no-release proof owner before its settlement transaction.
        transport.retainDispatchFence(); fenceRetained = true;
        claimed = await claimInvocationDispatch(this.driver, this.artifacts, this.owner, {
          runId, opId: prepared.opId, attempt: prepared.attempt, expectedRunRevision: readRun(this.driver, runId).revision,
          leaseEpoch: prepared.leaseEpoch, dispatchId: identityHash('cliq-installed-model-dispatch-v1', randomBytes(32).toString('hex')),
          brokerFenceTokenDigest: transport.brokerFenceTokenDigest,
        });
        const binding: ModelBrokerBinding = { runId, opId: claimed.opId, attempt: claimed.attempt,
          dispatchId: claimed.dispatchId!, dispatchJournalSeq: claimed.seq, requestRef: claimed.requestRef,
          requestDigest: initial.request.requestDigest, targetRef: initial.authority.targetRef, targetDigest: initial.authority.targetDigest,
          grantRef: claimed.grantRef!, supervisorInstanceId: claimed.supervisorInstanceId!, stateOwnerEpoch: claimed.stateOwnerEpoch!,
          leaseEpoch: claimed.leaseEpoch, brokerFenceTokenDigest: transport.brokerFenceTokenDigest };
        const gate = async <T>(release: () => Promise<T>): Promise<T> => {
          const cut = await readModelClaimCut(this.driver, this.artifacts, prepared);
          let fence: TimeFenceAdvance | undefined;
          let workerCut!: Parameters<RunExecution['assertCurrentModelWorker']>[0];
          this.driver.transaction(connection => {
            if (!this.supportsInstalledRuns() || this.released) throw new KernelStorageError('LEASE_FENCED', 'model broker is closing or its lane is unavailable');
            const now = sampleCanonicalNow();
            assertActiveStateOwner(connection, this.owner);
            token.assertHeld();
            currentModelAuthority(held, cut.authority.principalId, target.endpointRegistrationId,
              frozen.map(value => value.credentialGrantId), now, { endpoint: target, bindings: frozen });
            fence = advanceTimeFence(connection, this.owner.ownerEpoch, now);
            if (fence !== 'healthy') return;
            const live = assertLiveDispatchState(connection, this.owner, runId, cut.run.revision, binding.leaseEpoch, now);
            const history = readOperationJournal(connection, runId, prepared.opId);
            const current = readInvocationAttempt(connection, runId, prepared.opId, prepared.attempt);
            if (canonicalSha256(live.run) !== canonicalSha256(cut.run) || current.length !== 2 ||
                canonicalSha256(current[1]) !== canonicalSha256(claimed) ||
                readCheckpoint(connection, live.run.latestCheckpointId).contextManifestRef !== cut.checkpoint.contextManifestRef ||
                readHighestPreparedAttempt(connection, runId, prepared.opId)?.seq !== prepared.seq)
              throw new KernelStorageError('LEASE_FENCED', 'model release no longer owns its exact current permanent claim');
            assertModelGrantDispatch(cut.authority.grant, { run: live.run, prepared, history, now, includingCurrentClaim: true });
            workerCut = { runId, leaseEpoch: live.run.leaseEpoch, launchId: live.launch.launchId,
              generationRef: live.launch.workspaceGenerationRef, workerIdentityDigest: live.launch.workerIdentityDigest! };
          });
          requireHealthyFence(fence);
          execution.assertCurrentModelWorker(workerCut);
          token.assertHeld();
          return release();
        };
        // Only local credential redemption happened before the permanent claim.
        // Each async revalidation ends in a fresh synchronous cut; native queue
        // entry follows immediately with no await/callback/SQL transaction I/O.
        await gate(() => transport!.connect(binding));
        const response = await gate(() => transport!.releaseBody(binding));
        receivedResponse = true;
        await transport.close();
        this.modelTransports.delete(runId);
        token.assertHeld();
        try {
          const reader = agent.model.start(attempt.prepared, { status: response.status, mediaType: response.mediaType });
          reader.push(response.bodyBytes);
          const result = reader.finish(sampleCanonicalNow(), agent.resolveToolInput);
          this.installedModelCompletions.set(runId, { prepared, claimed, result });
        } finally {
          response.bodyBytes.fill(0);
        }
        return await this.settleInstalledModelCompletion(runId, agent);
      } catch (error) {
        // Unknown never becomes a no-release refund or a synthetic response.
        // Native closure is resource retirement only, not external-effect proof.
        const pendingClosure = claimed && transport && !receivedResponse
          ? { prepared, claimed, transport, initial } : undefined;
        if (pendingClosure) {
          this.installedModelClosures.set(runId, pendingClosure);
          this.modelTransports.set(runId, pendingClosure.transport);
        }
        if (transport) {
          await transport.close();
          if (!pendingClosure) this.modelTransports.delete(runId);
        }
        if (error instanceof ResourceRetirementError) throw error;
        if (error instanceof InstalledModelBrokerRefusalError) console.error(canonicalJsonBytes({ diagnosticOnly: true,
          scope: 'installed-model-broker', runId, opId: prepared.opId, attempt: prepared.attempt,
          ...(claimed ? { dispatchId: claimed.dispatchId, dispatchJournalSeq: claimed.seq } : {}), reason: error.reason }).toString('utf8'));
        const last = readInvocationAttempt(this.driver, runId, prepared.opId, prepared.attempt).at(-1);
        if (pendingClosure) {
          token.assertHeld();
          await this.settleInstalledModelClosure(runId);
          fenceRetained = false;
        } else if (last?.phase === 'prepared') {
          if (error instanceof InstalledModelAuthorizationError) {
            const { publishInstalledCredentialRedemptionRefusal } = await import('./credential-redemption-failure.js');
            const refusal = await publishInstalledCredentialRedemptionRefusal(this.driver, this.artifacts, this.owner, token, prepared);
            await failPreparation(undefined, refusal.ref);
            const inspector = supervisorInspectorIdentity(assertActiveStateOwner(this.driver, this.owner));
            const artifact = await this.artifacts.publishCanonical(inspector, inspector.format);
            await agent.stopForModelFailure({ expectedRunRevision: readRun(this.driver, runId).revision,
              inspectorIdentityRef: artifact.ref, inspectorIdentityDigest: inspector.identityDigest });
            this.requestInstalledRunStop(runId);
          } else await failPreparation(preparationError === error ? preparationError : undefined);
        }
        // Received observations retain their original settlement owner. Any
        // unproved claim remains explicit; neither a closed report nor an
        // ordinary error can manufacture a no-release refund or UNKNOWN.
        throw error;
      } finally {
        bodyBytes.fill(0);
        if (fenceRetained && transport && !this.installedModelClosures.has(runId)) {
          await transport.close();
          transport.releaseDispatchFence();
        }
      }
    };
    const bodyBytes = Buffer.from(attempt.prepared.outbound.bodyBytes);
    try {
      if (sha256Bytes(bodyBytes) !== initial.request.bodyBytesRef || bodyBytes.length !== initial.request.bodyByteCount)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'model compiled body differs from the permanent prepared request');
      return await withCredentialAuthorityLock(selected, dispatch);
    } catch (error) {
      // Only the real non-reentrant guard can refuse before this callback
      // enters. No native owner or permanent claim was created by this call.
      if (!callbackEntered && error instanceof CredentialScopeBusyError && !this.modelTransports.has(runId)) {
        const entries = readInvocationAttempt(this.driver, runId, prepared.opId, prepared.attempt);
        if (entries.length === 1 && entries[0]?.phase === 'prepared' && canonicalSha256(entries[0]) === canonicalSha256(prepared))
          await failPreparation(error);
      }
      throw error;
    } finally { bodyBytes.fill(0); }
  }

  async loadRunExecution(input: LoadRunExecutionInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    const runId = input.runId;
    if (this.executions.has(runId)) throw new KernelStorageError('REVISION_CONFLICT', 'Run already has an execution resource owner');
    const opening = this.ownInstalledAdmission(signal => loadRunExecution(this.driver, this.artifacts, this.owner, this.runtimeAuthority, input,
      () => this.closed || this.closeRequested || this.released, this.installedRuntime, this.installedAnchor, this, signal,
      phase => { if (this.installedRunPhases.has(runId)) this.installedRunPhases.set(runId, `drive_retirement_${phase}`); },
      installedRunDiagnosticsSubscribed() ? phase => {
        if (this.installedRunPhases.has(runId)) this.installedRunPhases.set(runId, phase);
        noteInstalledPublicationPhase(phase);
      } : undefined));
    this.executions.set(runId, opening);
    let scope: Awaited<typeof opening> | undefined;
    try {
      scope = await opening;
      if (this.closed || this.closeRequested || this.released) {
        await scope.close();
        throw new KernelStorageError('LEASE_FENCED', 'StateStore closed while loading execution');
      }
      this.loadedExecutionScopes.set(runId, scope);
      return scope.execution;
    } catch (error) {
      // A failed factory whose cleanup completed releases its reservation.
      // A resolved scope or unjoined opening must remain owned across close
      // retries, even when the original load caller receives an error.
      if (!scope && !(error instanceof ResourceRetirementError) && this.executions.get(runId) === opening) {
        this.executions.delete(runId);
      }
      throw error;
    }
  }

  /** Internal source producer, not a public wire method or accepted Run.
   * The whole factory, including validation/replay reads, is Store-owned before
   * its first asynchronous action; shutdown cancels and joins every operation. */
  async captureSubmittedSource(input: CaptureSubmittedSourceInput, diagnosis?: InstalledApplyDiagnostic): Promise<SourceInspectionAttemptV1> {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 2 ||
        !Object.hasOwn(input, 'request') || !Object.hasOwn(input, 'identity')) {
      throw new KernelStorageError('INVALID_REQUEST', 'source capture requires one inline request and authenticated identity');
    }
    // Keep the actual native frame owner separately from snapshotted data.
    const frameIdentity = input.identity;
    input = immutableSnapshot(input);
    const normalized = normalizeSourceInspectionRequest(input.request);
    const key = identityHash('cliq-source-inspection-task-v1', input.identity.principalId, normalized.request.method, normalized.request.admissionKey);
    const intent = sourceInspectionIntentDigest(input.identity.principalId, normalized.request);
    const existing = this.sourceInspections.get(key);
    const abort = new AbortController();
    const promise = Promise.resolve().then(async () => {
      abort.signal.throwIfAborted();
      await validateControlChannelClosure(this.artifacts.withReadSignal(abort.signal), this.owner, input.identity);
      abort.signal.throwIfAborted();
      assertActiveStateOwner(this.driver, this.owner);
      const { captureSubmittedSource, assertSourceInspectionRequestId } = await import('./source-inspection-owner.js');
      assertSourceInspectionRequestId(this.driver, input.identity.principalId, normalized.request,
        existing && identityHash('cliq-source-inspection-v1', input.identity.principalId, normalized.request.method, normalized.request.admissionKey, intent));
      if (existing) {
        if (existing.intent !== intent) throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'source key belongs to a different original intent');
        // Join one physical task, then bind this authenticated follower through
        // the ordinary retained replay path. A failed resource join propagates
        // as-is; it must never become a new capture of live source bytes.
        await existing.task.promise;
      }
      const bootstrap = this.runtimeAuthority;
      if (!bootstrap?.sourceInspection) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'trusted source inspection installation is not configured');
      abort.signal.throwIfAborted();
      if (normalized.request.method === 'run.apply') {
        const { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } = await import('./source-inspection.js');
        const retained = readSourceInspectionAttempt(this.driver, { principalId: input.identity.principalId, method: 'run.apply',
          admissionKey: normalized.request.admissionKey, admissionIntentDigest: intent });
        if (retained) {
          // Only retained data may select a replay profile. The original
          // owner verifies that complete target/runtime/source graph before
          // returning; no current source selection, capacity or FD is opened.
          const { readSourceInspectionTargetData } = await import('./source-target.js');
          const target = await readSourceInspectionTargetData(this.artifacts.withReadSignal(abort.signal), retained,
            readSourceInspectionOriginalRequest(this.driver, retained.inspectionId));
          const sandboxProfile = decodeSandboxProfile(await this.artifacts.withReadSignal(abort.signal).readCanonical(target.target.sandboxProfileRef));
          const { replaySubmittedSource } = await import('./source-inspection-owner.js');
          const replay = await replaySubmittedSource(this.driver, this.artifacts.withReadSignal(abort.signal), this.owner,
            { bundle: bootstrap.bundle, releaseKeys: bootstrap.releaseKeys, ...bootstrap.sourceInspection, sandboxProfile },
            normalized.request, input.identity, abort.signal);
          if (!replay) throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery source replay lost its original retained attempt');
          return replay;
        }
      }
      if (this.installedRuntime) {
        assertCurrentControlFrame(this.owner, frameIdentity); assertActiveStateOwner(this.driver, this.owner);
        // A joined capture may have just committed its original request index.
        // Preserve that conflict before this read-only, non-reserving refusal.
        assertSourceInspectionRequestId(this.driver, input.identity.principalId, normalized.request);
        assertInstalledRunAdmissionCapacity(this.driver);
      }
      const deliverySource = normalized.request.method === 'run.apply'
        ? await readVerifiedDeliverySource(this.driver, this.artifacts.withReadSignal(abort.signal), this.owner, {
          principalId: input.identity.principalId, sourceRunId: normalized.request.sourceRunId,
          expectedRunResultRef: normalized.request.expectedRunResultRef, signal: abort.signal }) : undefined;
      const sandboxProfile = deliverySource
        ? decodeSandboxProfile(await this.artifacts.withReadSignal(abort.signal).readCanonical(deliverySource.spec.sandboxProfileRef))
        : normalized.request.method === 'run.submit' && this.installedRuntime ? installedSandboxProfile(normalized.request.sandboxResources) : undefined;
      diagnosis?.stage('capture');
      return captureSubmittedSource(this.driver, this.artifacts, this.owner,
        { bundle: bootstrap.bundle, releaseKeys: bootstrap.releaseKeys, ...bootstrap.sourceInspection,
          ...(sandboxProfile ? { sandboxProfile } : {}) },
        { ...input, identity: frameIdentity, ...(deliverySource ? { deliverySource } : {}) }, abort.signal, this.installedRuntime, this.installedAnchor);
    });
    const task: SourceInspectionTask = { abort, promise };
    this.sourceInspectionTasks.add(task);
    if (!existing) this.sourceInspections.set(key, { intent, task });
    const settled = (error?: unknown) => {
      // A rejected resource join is retained across close retries. Ordinary
      // validation failures own nothing once their complete task has ended.
      if (!(error instanceof ResourceRetirementError)) {
        if (this.sourceInspections.get(key)?.task === task) this.sourceInspections.delete(key);
        this.sourceInspectionTasks.delete(task);
      }
    };
    void promise.then(() => settled(), settled);
    return promise;
  }

  claimInvocationDispatch(input: ClaimInvocationDispatchInput) {
    return claimInvocationDispatch(this.driver, this.artifacts, this.owner, input);
  }

  completeInvocation(
    input: SettleInvocationInput & {
      resultRef?: string;
      receiptRef?: string;
      consumed: import('../kernel/types.js').BudgetUsage;
    }
  ) {
    return completeInvocation(this.driver, this.artifacts, this.owner, input);
  }

  failInvocationBeforeDispatch(input: SettleInvocationInput & { errorRef: string }) {
    return failInvocationBeforeDispatch(this.driver, this.artifacts, this.owner, input);
  }

  failClaimedInvocationWithoutRelease(
    input: SettleInvocationInput & { errorRef: string; evidenceRef: string; evidenceDigest: string }
  ) {
    return failClaimedInvocationWithoutRelease(this.driver, this.artifacts, this.owner, input);
  }

  markInvocationUnknown(
    input: SettleInvocationInput & { evidenceRef: string; evidenceDigest: string }
  ) {
    return markInvocationUnknown(this.driver, this.artifacts, this.owner, input);
  }

  abandonUnknownInvocation(input: {
    runId: string;
    opId: string;
    attempt: number;
    attestationRef: string;
  }) {
    return abandonUnknownInvocation(this.driver, this.artifacts, this.owner, input);
  }

  getSession(sessionId: string): Session {
    return readSession(this.driver, sessionId);
  }

  /** Canonical bounded queries shared by clients; identity comes from the control channel, never the request. */
  readControl(request: ReadControlRequest, identity: AuthenticatedControlIdentity) {
    if (this.closed || this.closeRequested || this.released)
      return Promise.reject(new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed'));
    // Register this complete query producer before its first await, retaining
    // StateOwner until a cancelled CAS stream has joined its original handles.
    return this.ownInstalledAdmission(signal => readControl(this.driver, this.artifacts, this.owner, request, identity, signal));
  }

  getRun(runId: string): Run {
    return readRun(this.driver, runId);
  }

  readRecoveryClosure(runId: string): Promise<RecoveryClosureV1> {
    return readRecoveryClosure(this.driver, this.artifacts, runId);
  }

  beginWorkerRecovery(input: BeginWorkerRecoveryInput): Promise<Run> {
    return beginWorkerRecovery(this.driver, this.artifacts, this.owner, input);
  }

  beginWorkerRecoveryProbe(input: { runId: string; expectedRunRevision: number }) {
    if (this.closed || this.closeRequested || this.released) {
      return Promise.reject(new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed'));
    }
    return beginWorkerRecoveryProbe(this.driver, this.artifacts, this.owner, input);
  }

  async closeWorkerRecoveryProbe(input: { runId: string; expectedRunRevision: number }) {
    input = immutableSnapshot(input);
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    const opening = this.executions.get(input.runId);
    if (opening) return (await opening).closeWorkerRecoveryProbe(input);
    return closeWorkerRecoveryProbe(this.driver, this.artifacts, this.owner, input);
  }

  recoverCanonicalTime(): TimeFenceAdvance {
    let outcome!: TimeFenceAdvance;
    this.driver.transaction((connection) => {
      assertActiveStateOwner(connection, this.owner);
      outcome = recoverRegressedTimeFence(connection, this.owner.ownerEpoch);
    });
    return outcome;
  }

  /** Revoke producers before a control service waits for its active handlers.
   * This is not a join, worker fence or permission to release StateOwner. */
  beginClose(): void {
    if (this.closed) return;
    if (!this.closeRequested && this.installedRuntime && installedRunDiagnosticsSubscribed()) {
      noteInstalledStoreStop({ driverTasks: this.installedRunTasks.size, agentLoads: this.installedAgentLoads.size,
        admissions: this.installedAdmissionTasks.size, retainedFailures: this.installedRunFailures.size,
        globalFailure: this.schedulerFailure !== undefined, phases: [...this.installedRunPhases.values()] });
    }
    if (!this.closeRequested && this.installedRuntime && this.installedRunTasks.size) {
      // A single fixed, secret-free observation at the actual stop boundary.
      // It neither extends the stop deadline nor supplies recovery evidence.
      try {
        const phases: Partial<Record<NonNullable<ReturnType<typeof this.installedRunPhases.get>>, number>> = {};
        for (const phase of this.installedRunPhases.values()) phases[phase] = (phases[phase] ?? 0) + 1;
        console.error(canonicalJsonBytes({ diagnosticOnly: true, scope: 'installed-shutdown-progress', phases,
          driverTasks: this.installedRunTasks.size, agentLoads: this.installedAgentLoads.size,
          admissions: this.installedAdmissionTasks.size, modelOperations: this.modelOperations.size,
          modelCompletions: this.installedModelCompletions.size, modelClosures: this.installedModelClosures.size }).toString('utf8'));
      } catch { /* Reporting must not prevent synchronous revocation. */ }
    }
    // The gate is synchronous: existing execution references cannot dispatch
    // while listeners/opening resources are being joined.
    this.closeRequested = true;
    clearTimeout(this.installedMaintenanceTimer); this.installedMaintenanceTimer = undefined;
    for (const scope of this.installedAgents.values())
      scope.readAbort?.abort(new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed'));
    // Closing revokes this Store's producers with the same typed fence used
    // by new calls; the signal is cancellation, never proof of their join.
    for (const task of this.installedAdmissionTasks)
      task.abort.abort(new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed'));
    for (const task of this.sourceInspectionTasks) task.abort.abort();
    const credential = installedCredentialFinalizers.get(this);
    if (credential?.inspection && !credential.inspectionJoin) {
      try {
        // Enter the exact native inspection owner's cancellation before the
        // service joins its handler. The handler retains and reawaits this
        // memoized join inside its still-held credential authority scope.
        credential.inspectionJoin = credential.inspection.cancelAndJoin();
        void credential.inspectionJoin.catch(error => {
          credential.retirementFailure ??= error instanceof ResourceRetirementError ? error :
            new ResourceRetirementError('credential inspection cancellation did not retire', error);
        });
      } catch (error) {
        credential.retirementFailure ??= new ResourceRetirementError('credential inspection cancellation did not start', error);
      }
    }
    for (const transport of this.modelTransports.values()) {
      try {
        // Native close starts revocation synchronously and memoizes its join.
        // Keep the map and original dispatch fence through typed settlement;
        // final close reawaits that same join, including a failed retirement.
        void transport.close().catch(() => {});
      } catch (error) {
        this.closeRevocationFailure ??= new ResourceRetirementError('StateStore producer revocation did not start cleanly', error);
      }
    }
    for (const scope of this.loadedExecutionScopes.values()) {
      try {
        // Revoke the original pending producer before installedRunTasks are
        // drained. Its memoized join remains owned by final scope.close(); an
        // idle worker backing a model settlement is not fenced by this phase.
        void scope.beginClose().catch(() => {});
      } catch (error) {
        this.closeRevocationFailure ??= new ResourceRetirementError('StateStore execution revocation did not start cleanly', error);
      }
    }
  }

  close(): Promise<void> {
    if (this.closed) return Promise.resolve();
    if (this.closing !== undefined) return this.closing;
    this.beginClose();
    const attempt = (async () => {
      const admissionJoins = await Promise.allSettled([...this.installedAdmissionTasks].map(task => task.promise));
      // Retire transports and join driver tasks before fencing workers or
      // closing their sole SQL owner; no key/request owner outlives StateOwner.
      const brokerJoins = await Promise.allSettled([...this.modelTransports.values()].map(transport => transport.close()));
      const producerJoins = await Promise.allSettled([...this.modelOperations.values(), ...this.installedAgentLoads.values()]);
      const driverJoins = await Promise.allSettled([...this.installedRunTasks.values()]);
      const maintenanceJoins = await Promise.allSettled(this.installedMaintenance ? [this.installedMaintenance] : []);
      const closureJoins = await Promise.allSettled([...this.installedModelClosures.keys()]
        .map(runId => this.settleInstalledModelClosure(runId)));
      const completionJoins = await Promise.allSettled([...this.installedModelCompletions.keys()].map(async runId => {
        // Retain StateOwner and the observed result rather than discarding it
        // on shutdown after a failed durable settlement. A close retry may
        // settle it once the actual storage failure has been repaired.
        const agent = this.installedAgents.get(runId)?.agent;
        if (!agent || agent.operation !== 'agent') throw new KernelStorageError('RECOVERY_REQUIRED', 'received model result retains its original agent owner');
        await this.settleInstalledModelCompletion(runId, agent);
      }));
      const results = await Promise.allSettled([
        ...[...this.controlListeners].map(listener => listener.close()),
        ...[...this.sourceInspectionTasks].map(async task => {
          try { await task.promise; }
          catch (error) { if (error instanceof ResourceRetirementError) throw error; }
        }),
        (async () => {
          const credential = installedCredentialFinalizers.get(this);
          try { await credential?.task; }
          catch (error) { if (error instanceof ResourceRetirementError) throw error; }
          if (credential?.retirementFailure) throw credential.retirementFailure;
        })(),
        ...[...this.executions.entries()].map(async ([runId, opening]) => {
          let scope: Awaited<typeof opening> | undefined;
          try { scope = await opening; await scope.close(); }
          catch (error) {
            if (scope || error instanceof ResourceRetirementError) throw error;
            // Ordinary failed validation owns no outstanding resources; it
            // must not make an otherwise successful Store shutdown fail.
            if (this.executions.get(runId) === opening) this.executions.delete(runId);
          }
        })
      ]);
      // A failed broker join cannot skip independent listener/source/worker
      // revocation. Every owner is joined, but StateOwner stays held on any
      // retirement uncertainty; neither failure becomes a positive receipt.
      const failure = [...brokerJoins, ...closureJoins, ...completionJoins,
        ...admissionJoins.filter(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError),
        ...producerJoins.filter(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError),
        ...driverJoins.filter(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError),
        ...maintenanceJoins.filter(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError), ...results]
        .find(result => result.status === 'rejected');
      if (this.closeRevocationFailure) throw this.closeRevocationFailure;
      if (failure?.status === 'rejected') throw failure.reason;
      this.executions.clear();
      this.loadedExecutionScopes.clear();
      if (!this.released) {
        await retireAbandonedPreactivations(this.driver, this.artifacts, this.owner,
          this.runtimeAuthority?.execution && { ...this.runtimeAuthority.execution,
            runtimeAuthority: { bundle: this.runtimeAuthority.bundle, releaseKeys: this.runtimeAuthority.releaseKeys } },
          this.installedRuntime, this.installedAnchor);
        await gracefullyReleaseStateOwner(this.driver, this.artifacts, this.owner);
        this.released = true;
      }
      this.driver.close();
      this.owner.filesystem.close();
      this.closed = true;
      unretiredStateStoreClosings.delete(this);
    })();
    this.closing = attempt.catch((error: unknown) => {
      unretiredStateStoreClosings.add(this);
      this.closing = undefined;
      // Failed close retains the owner and permits its exact recovery path;
      // it never makes a retired execution resource reusable.
      this.closeRequested = false;
      throw error;
    });
    return this.closing;
  }
}

export async function openStateStore(stateRoot: string, runtimeAuthority?: StateStoreRuntimeAuthority,
  installedRuntime?: HeldInstalledRuntime, installedAnchor?: HeldInstalledAnchor): Promise<StateStore> {
  return StateStore.open(stateRoot, runtimeAuthority, installedRuntime, installedAnchor);
}

async function assertInstalledRootBinding(stateRoot: string, heldLock: HeldStateOwnerLock, installed: InstalledRuntimeBorrow) {
  try {
    await installed.revalidate();
    return await assertInstalledObservedRootBinding(stateRoot, heldLock, installed);
  } catch (cause) {
    if (cause instanceof KernelStorageError) throw cause;
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'held installed root validation failed', { cause });
  }
}

/** A copied inventory never substitutes for the real owner/root checks. The
 * caller must obtain a fresh fixed observation at each original validation cut. */
async function assertInstalledObservedRootBinding(stateRoot: string, heldLock: HeldStateOwnerLock,
  installed: Pick<InstalledRuntimeObservation, 'stateRoot' | 'casRoot'>) {
  try {
    assertStateOwnerLock(heldLock);
    if (installed.stateRoot.canonicalPath !== stateRoot ||
        installed.stateRoot.deviceId !== heldLock.root.deviceId ||
        installed.stateRoot.fileId !== heldLock.root.fileId || installed.stateRoot.ownerUid !== heldLock.root.ownerUid) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed StateRoot differs from the native owner lock root');
    }
    const info = await lstat(path.join(stateRoot, KERNEL_CAS_DIRECTORY), { bigint: true });
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o7777n) !== 0o700n ||
        info.uid !== BigInt(installed.casRoot.ownerUid) || unsignedDecimalId(info.dev) !== installed.casRoot.deviceId ||
        unsignedDecimalId(info.ino) !== installed.casRoot.fileId) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed CAS differs from its held private directory');
    }
    assertStateOwnerLock(heldLock);
    return info;
  } catch (cause) {
    if (cause instanceof KernelStorageError) throw cause;
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'held installed root validation failed', { cause });
  }
}

/** Only genesis calls this with the producer's seed and its own staged objects;
 * a client cannot supply the expected namespace or substitute a CAS locator. */
async function assertInstalledGenesisNamespace(stateRoot: string, heldLock: HeldStateOwnerLock,
  artifacts: ArtifactCatalog, installed: InstalledRuntimeBorrow, expectedArtifacts: readonly PublishedArtifact[]): Promise<void> {
  try {
    const expected = new Map<string, number>();
    for (const artifact of expectedArtifacts) {
      const prior = expected.get(artifact.ref);
      if (prior !== undefined && prior !== artifact.byteLength)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed genesis object has conflicting byte counts');
      expected.set(artifact.ref, artifact.byteLength);
    }
    const assertNames = async () => {
      const names = await readdir(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
      if (names.length !== expected.size || names.some(name => !expected.has(name)))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed genesis CAS is not the exact held seed and staged objects');
    };
    await assertInstalledRootBinding(stateRoot, heldLock, installed);
    await assertNames();
    for (const [ref, byteCount] of expected) {
      for await (const _chunk of artifacts.readChunks(ref, byteCount)) { /* Complete rehash and owned 0400/single-link checks. */ }
    }
    await assertInstalledRootBinding(stateRoot, heldLock, installed);
    await assertNames();
    assertStateOwnerLock(heldLock);
  } catch (cause) {
    if (cause instanceof KernelStorageError) throw cause;
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed genesis CAS validation failed', { cause });
  }
}

async function acquireOrBootstrapStateOwner(
  stateRoot: string,
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  native: NativeStateOwner,
  heldLock: HeldStateOwnerLock,
  runtimeBundle?: RuntimeBundleManifest,
  installed?: InstalledRuntimeBorrow
): Promise<Extract<StateOwnerRecordV1, { state: 'active' }>> {
  assertContiguousStateOwnerHistory(driver);
  const existingOwner = readActiveStateOwner(driver);
  const fence = readTimeFence(driver);
  const latestOwner = readLatestStateOwner(driver);
  if (latestOwner !== undefined) {
    if (fence === undefined || fence.stateOwnerEpoch !== latestOwner.ownerEpoch) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner history and time fence do not match');
    }
    if (existingOwner !== undefined && existingOwner.rowDigest !== latestOwner.rowDigest) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'active state owner is not the latest owner');
    }
    if (latestOwner.state === 'terminal' && latestOwner.terminalReason !== 'graceful_release') {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'latest state owner is not cleanly acquirable');
    }
    const retainedRuntime = await artifacts.readCanonical<{ format?: string }>(latestOwner.runtimeBundleRef);
    const supervisor = runtimeBundle?.entries.find((entry) => entry.role === 'supervisor');
    if (runtimeBundle ? canonicalSha256(runtimeBundle) !== latestOwner.runtimeBundleRef ||
        runtimeBundle.manifestDigest !== latestOwner.runtimeBundleManifestDigest ||
        supervisor?.entryId !== latestOwner.supervisorEntryId || supervisor.version !== latestOwner.supervisorEntryVersion ||
        supervisor.digest !== latestOwner.supervisorExecutableDigest :
        retainedRuntime.format !== 'cliq-kernel-schema-manifest-v1') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'reopen requires the same signed Supervisor authority; runtime upgrades need their own transition');
    }
    return acquireSuccessorStateOwner(stateRoot, driver, artifacts, latestOwner, native, heldLock);
  }
  if (fence !== undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence exists without state owner history');
  }
  assertPristineKernelSchema(driver);
  assertFreshAuthorityDatabaseEmpty(driver);

  const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
  const seedArtifacts: PublishedArtifact[] = installed?.seed.map(object => ({ ref: object.artifactRef,
    byteLength: object.byteCount, mediaType: object.mediaType, schemaKind: object.schemaKind })) ?? [];
  if (installed) {
    await assertInstalledGenesisNamespace(stateRoot, heldLock, artifacts, installed, seedArtifacts);
  } else if ((await readdir(casRoot)).length !== 0) {
    throw new KernelStorageError(
      'RECOVERY_REQUIRED',
      'refusing fresh_empty genesis over a non-empty CAS namespace'
    );
  }

  const now = sampleCanonicalNow();
  const platform = hostPlatform();
  const uid = requireEffectiveUid();
  const casInfo = await lstat(casRoot, { bigint: true });
  assertStateOwnerLock(heldLock);
  const stateSchemaVersion = readSchemaUserVersion(driver);
  if (stateSchemaVersion !== KERNEL_STATE_SCHEMA_VERSION)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'genesis state schema differs from the opened current schema');

  const stateRootIdentity = stateRootIdentityFromDescriptor(stateRoot, heldLock.root);
  const stateRootArtifact = await artifacts.publishCanonical(stateRootIdentity, 'cliq-state-root-identity-v1');

  const processIdentity = await currentProcessIdentity(native, now);
  const processArtifact = await artifacts.publishCanonical(processIdentity, 'cliq-platform-process-identity-v1');

  const lockIdentity: StateLockIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-state-lock-identity-v1',
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    canonicalRootRelativePath: 'runtime/state-owner.lock',
    deviceId: heldLock.lock.deviceId,
    fileId: heldLock.lock.fileId,
    ownerUid: heldLock.lock.ownerUid,
    mode: 384,
    linkCount: 1,
    identityDigest: ''
  };
  lockIdentity.identityDigest = digestOmitting(lockIdentity, 'identityDigest');
  const lockArtifact = await artifacts.publishCanonical(lockIdentity, 'cliq-state-lock-identity-v1');

  const schemaDigest = sha256Bytes(Buffer.from(KERNEL_SCHEMA_SQL, 'utf8'));
  const schemaManifest = {
    schemaVersion: 1,
    format: 'cliq-kernel-schema-manifest-v1',
    applicationId: KERNEL_SQLITE_APPLICATION_ID,
    userVersion: stateSchemaVersion,
    schemaDigest,
    manifestDigest: ''
  };
  schemaManifest.manifestDigest = digestOmitting(schemaManifest, 'manifestDigest');
  const schemaArtifact = await artifacts.publishCanonical(schemaManifest, 'cliq-kernel-schema-manifest-v1');
  const runtimeArtifact = runtimeBundle ? await artifacts.publishCanonical(runtimeBundle, 'cliq-runtime-bundle-v1') : schemaArtifact;
  const supervisor = runtimeBundle?.entries.find((entry) => entry.role === 'supervisor');

  const emptyDatabase = {
    schemaVersion: 1,
    format: 'cliq-kernel-empty-database-v1',
    applicationId: KERNEL_SQLITE_APPLICATION_ID,
    userVersion: stateSchemaVersion,
    contentDigest: canonicalSha256({
      applicationId: KERNEL_SQLITE_APPLICATION_ID,
      userVersion: stateSchemaVersion,
      tables: KERNEL_AUTHORITY_TABLES.length
    })
  };
  const databaseArtifact = await artifacts.publishCanonical(emptyDatabase, 'cliq-kernel-empty-database-v1');
  const seedEntries = installed?.seed.map(({ artifactRef, byteCount }) => ({ artifactRef, byteCount })) ?? [];
  let seedBytes = 0;
  for (const { byteCount } of seedEntries) {
    if (!Number.isSafeInteger(byteCount) || byteCount < 0 || byteCount > Number.MAX_SAFE_INTEGER - seedBytes)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed CAS seed byte count is not a safe integer');
    seedBytes += byteCount;
  }

  const casNamespace = {
    schemaVersion: 1,
    format: 'cliq-cas-namespace-manifest-v1',
    snapshotBoundary: 'generation_birth',
    namespaceId: identityHash('cliq-cas-namespace-v1', stateRootIdentity.identityDigest, 'cas'),
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    canonicalRootRelativePath: KERNEL_CAS_DIRECTORY,
    ownerUid: uid,
    deviceId: unsignedDecimalId(casInfo.dev),
    directoryFileId: unsignedDecimalId(casInfo.ino),
    mode: 448,
    entries: seedEntries,
    objectCount: seedEntries.length,
    totalBytes: seedBytes,
    rootDigest: canonicalSha256(seedEntries),
    manifestDigest: ''
  };
  casNamespace.manifestDigest = digestOmitting(casNamespace, 'manifestDigest');
  const casArtifact = await artifacts.publishCanonical(casNamespace, 'cliq-cas-namespace-manifest-v1');

  const generation: KernelGenerationIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-kernel-generation-identity-v1',
    generationId: installed ? identityHash('cliq-kernel-generation-v1', stateRootIdentity.identityDigest, 'fresh_installed', installed.bundleDigest) :
      identityHash('cliq-kernel-generation-v1', stateRootIdentity.identityDigest, 'fresh_empty'),
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    databaseImageRef: databaseArtifact.ref,
    databaseImageDigest: databaseArtifact.ref,
    databaseIdentityDigest: databaseArtifact.ref,
    databaseContentDigest: emptyDatabase.contentDigest,
    casNamespaceManifestRef: casArtifact.ref,
    casNamespaceManifestDigest: casNamespace.manifestDigest,
    casNamespaceId: casNamespace.namespaceId,
    casRootDigest: casNamespace.rootDigest,
    stateSchemaVersion,
    generationDigest: '',
    ...(installed ? { origin: 'fresh_installed' as const, runtimeBundleRef: installed.bundleDigest,
      runtimeBundleManifestDigest: installed.bundle.manifestDigest,
      modelAuthoritySource: installed.modelAuthority
        ? { kind: 'present' as const, closureRef: installed.modelAuthority.closureRef,
          closureDigest: installed.modelAuthority.closure.closureDigest }
        : { kind: 'none' as const } } : { origin: 'fresh_empty' as const }),
    pristineSchemaManifestRef: schemaArtifact.ref,
    pristineSchemaManifestDigest: schemaManifest.manifestDigest,
    pristineSchemaDigest: schemaDigest
  };
  generation.generationDigest = digestOmitting(generation, 'generationDigest');
  const generationArtifact = await artifacts.publishCanonical(generation, 'cliq-kernel-generation-identity-v1');

  const supervisorInstanceId = identityHash('cliq-supervisor-instance-v1', processIdentity.identityDigest, now);
  const instanceNonceDigest = sha256Bytes(randomBytes(32));
  const acquisition: StateOwnerAcquisitionEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-state-owner-acquisition-evidence-v1',
    ownerEpoch: 1,
    supervisorInstanceId,
    runtimeBundleRef: runtimeArtifact.ref,
    runtimeBundleManifestDigest: runtimeBundle?.manifestDigest ?? schemaManifest.manifestDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: lockArtifact.ref,
    stateLockIdentityDigest: lockIdentity.identityDigest,
    instanceNonceDigest,
    acquiredAt: now,
    evidenceDigest: '',
    kind: 'genesis',
    kernelGenerationIdentityRef: generationArtifact.ref,
    kernelGenerationIdentityDigest: generation.generationDigest,
    ownerTableObservation: 'empty'
  };
  acquisition.evidenceDigest = digestOmitting(acquisition, 'evidenceDigest');
  const acquisitionArtifact = await artifacts.publishCanonical(
    acquisition,
    'cliq-state-owner-acquisition-evidence-v1'
  );

  const owner: Extract<StateOwnerRecordV1, { state: 'active' }> = {
    schemaVersion: 1,
    ownerEpoch: 1,
    supervisorInstanceId,
    runtimeBundleRef: runtimeArtifact.ref,
    runtimeBundleManifestDigest: runtimeBundle?.manifestDigest ?? schemaManifest.manifestDigest,
    supervisorEntryId: supervisor?.entryId ?? 'state-store',
    supervisorEntryVersion: supervisor?.version ?? 'm2',
    supervisorExecutableDigest: processIdentity.executableImageDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: lockArtifact.ref,
    stateLockIdentityDigest: lockIdentity.identityDigest,
    acquisitionEvidenceRef: acquisitionArtifact.ref,
    acquisitionEvidenceDigest: acquisition.evidenceDigest,
    instanceNonceDigest,
    acquiredAt: now,
    rowDigest: '',
    state: 'active',
    rowVersion: 1
  };
  owner.rowDigest = digestOmitting(owner, 'rowDigest');

  const genesisArtifacts = [stateRootArtifact, processArtifact, lockArtifact, schemaArtifact,
    ...(runtimeBundle ? [runtimeArtifact] : []), databaseArtifact, casArtifact, generationArtifact, acquisitionArtifact];
  const rootedArtifacts = [...seedArtifacts, ...genesisArtifacts];
  if (installed) {
    // The birth snapshot is acyclic: only the independently held seed appears
    // in it, while this final publication cut also permits these exact objects.
    await assertInstalledGenesisNamespace(stateRoot, heldLock, artifacts, installed, rootedArtifacts);
  }

  driver.transaction((connection) => {
    assertStateOwnerLock(heldLock);
    assertPristineKernelSchema(connection);
    assertFreshAuthorityDatabaseEmpty(connection);
    const schemaNow = connection.prepare('PRAGMA user_version').get<{ user_version: unknown }>();
    if (schemaNow?.user_version !== BigInt(stateSchemaVersion))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'genesis state schema changed before owner publication');
    insertStateOwnerArtifacts(
      connection,
      rootedArtifacts,
      now
    );
    insertGenesisTimeFence(connection, 1, now);
    connection
      .prepare(
        `INSERT INTO state_owners (owner_epoch, supervisor_instance_id, record_json, state, row_digest)
         VALUES (1, ?, ?, 'active', ?)`
      )
      .run(supervisorInstanceId, JSON.stringify(owner), owner.rowDigest);
  });
  return owner;
}

function assertPriorProcessDead(heldLock: HeldStateOwnerLock, identity: PlatformProcessIdentityV1): void {
  try { heldLock.assertPriorProcessDead(identity.pid, identity.processStartToken); }
  catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', error instanceof Error ? error.message : 'prior StateOwner process death is unproven');
  }
}

async function acquireSuccessorStateOwner(
  stateRoot: string,
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  prior: StateOwnerRecordV1,
  native: NativeStateOwner,
  heldLock: HeldStateOwnerLock
): Promise<Extract<StateOwnerRecordV1, { state: 'active' }>> {
  await stateOwnerFilesystemFromArtifacts(stateRoot, artifacts, prior, heldLock);
  const history = await readRetainedStateOwnerHistory(driver, artifacts, prior.ownerEpoch);
  const priorProcess = history.entries.at(-1)!.process;

  const currentFence = readTimeFence(driver);
  if (currentFence === undefined || currentFence.stateOwnerEpoch !== prior.ownerEpoch) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence does not match prior owner history');
  }
  const acquiredAt = sampleCanonicalNow();
  if (prior.state === 'active') assertPriorProcessDead(heldLock, priorProcess);
  const artifactCreatedAt = acquiredAt >= currentFence.lastAcceptedAt
    ? acquiredAt
    : currentFence.lastAcceptedAt;
  const processIdentity = await currentProcessIdentity(native, acquiredAt);
  const processArtifact = await artifacts.publishCanonical(
    processIdentity,
    'cliq-platform-process-identity-v1'
  );
  const ownerEpoch = prior.ownerEpoch + 1;
  const supervisorInstanceId = identityHash(
    'cliq-supervisor-instance-v1',
    processIdentity.identityDigest,
    acquiredAt,
    String(ownerEpoch)
  );
  const instanceNonceDigest = sha256Bytes(randomBytes(32));
  let terminal: Extract<StateOwnerRecordV1, { state: 'terminal' }>;
  let transitionArtifact: PublishedArtifact | undefined;
  if (prior.state === 'active') {
    const transition: StateOwnerTransitionEvidenceV1 = {
      schemaVersion: 1, format: 'cliq-state-owner-transition-evidence-v1',
      priorOwnerEpoch: prior.ownerEpoch, priorSupervisorInstanceId: prior.supervisorInstanceId,
      priorProcessIdentityRef: prior.processIdentityRef, priorProcessIdentityDigest: prior.processIdentityDigest,
      stateLockIdentityRef: prior.stateLockIdentityRef, stateLockIdentityDigest: prior.stateLockIdentityDigest,
      observedAt: acquiredAt, evidenceDigest: '', kind: 'superseded_after_owner_death',
      priorProcessObservation: 'absent_or_start_token_mismatch', successorOwnerEpoch: ownerEpoch,
      successorSupervisorInstanceId: supervisorInstanceId, successorRuntimeBundleRef: prior.runtimeBundleRef,
      successorRuntimeBundleManifestDigest: prior.runtimeBundleManifestDigest,
      successorProcessIdentityRef: processArtifact.ref, successorProcessIdentityDigest: processIdentity.identityDigest,
      successorInstanceNonceDigest: instanceNonceDigest
    };
    transition.evidenceDigest = digestOmitting(transition, 'evidenceDigest');
    transitionArtifact = await artifacts.publishCanonical(transition, 'cliq-state-owner-transition-evidence-v1');
    terminal = terminalStateOwnerRecord(prior, transition, transitionArtifact.ref, artifactCreatedAt);
  } else {
    terminal = prior;
  }
  const acquisition: StateOwnerAcquisitionEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-state-owner-acquisition-evidence-v1',
    ownerEpoch,
    supervisorInstanceId,
    runtimeBundleRef: prior.runtimeBundleRef,
    runtimeBundleManifestDigest: prior.runtimeBundleManifestDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: prior.stateLockIdentityRef,
    stateLockIdentityDigest: prior.stateLockIdentityDigest,
    instanceNonceDigest,
    acquiredAt,
    evidenceDigest: '',
    ...(prior.state === 'active'
      ? { kind: 'takeover_after_owner_death' as const, priorTerminalReason: 'superseded_after_owner_death' as const }
      : { kind: 'acquire_after_graceful_release' as const, priorTerminalReason: 'graceful_release' as const }),
    priorOwnerEpoch: prior.ownerEpoch,
    priorTerminalRowDigest: terminal.rowDigest,
    priorTransitionEvidenceRef: terminal.transitionEvidenceRef,
    priorTransitionEvidenceDigest: terminal.transitionEvidenceDigest
  };
  acquisition.evidenceDigest = digestOmitting(acquisition, 'evidenceDigest');
  const acquisitionArtifact = await artifacts.publishCanonical(
    acquisition,
    'cliq-state-owner-acquisition-evidence-v1'
  );
  const owner: Extract<StateOwnerRecordV1, { state: 'active' }> = {
    schemaVersion: 1,
    ownerEpoch,
    supervisorInstanceId,
    runtimeBundleRef: prior.runtimeBundleRef,
    runtimeBundleManifestDigest: prior.runtimeBundleManifestDigest,
    supervisorEntryId: prior.supervisorEntryId,
    supervisorEntryVersion: prior.supervisorEntryVersion,
    supervisorExecutableDigest: processIdentity.executableImageDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: prior.stateLockIdentityRef,
    stateLockIdentityDigest: prior.stateLockIdentityDigest,
    acquisitionEvidenceRef: acquisitionArtifact.ref,
    acquisitionEvidenceDigest: acquisition.evidenceDigest,
    instanceNonceDigest,
    acquiredAt,
    rowDigest: '',
    state: 'active',
    rowVersion: 1
  };
  owner.rowDigest = digestOmitting(owner, 'rowDigest');

  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertStateOwnerLock(heldLock);
    assertContiguousStateOwnerHistory(connection);
    history.assertUnchanged(connection);
    const active = readActiveStateOwner(connection);
    if (prior.state === 'active' ? active?.rowDigest !== prior.rowDigest : active !== undefined) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'another state owner acquired authority');
    }
    const lockedPrior = readLatestStateOwner(connection);
    if (
      lockedPrior === undefined ||
      lockedPrior.state !== prior.state ||
      lockedPrior.ownerEpoch !== prior.ownerEpoch ||
      lockedPrior.rowDigest !== prior.rowDigest
    ) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'prior state owner changed during acquisition');
    }
    const committedAt = sampleCanonicalNow();
    if (prior.state === 'active') {
      const age = parseCanonicalTime(committedAt) - parseCanonicalTime(acquiredAt);
      if (age < 0 || age > 5000) throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner death observation is outside the five-second commit window');
      assertPriorProcessDead(heldLock, priorProcess);
    }
    fenceOutcome = transferTimeFenceOwner(connection, prior.ownerEpoch, ownerEpoch, committedAt);
    insertStateOwnerArtifacts(connection, [processArtifact, ...(transitionArtifact ? [transitionArtifact] : []), acquisitionArtifact], artifactCreatedAt);
    if (prior.state === 'active') {
      const changed = connection.prepare(`UPDATE state_owners SET record_json = ?, state = 'terminal', row_digest = ?
        WHERE owner_epoch = ? AND state = 'active' AND row_digest = ?`)
        .run(JSON.stringify(terminal), terminal.rowDigest, BigInt(prior.ownerEpoch), prior.rowDigest);
      if (changed.changes !== 1n) throw new KernelStorageError('RECOVERY_REQUIRED', 'prior state owner changed during takeover');
    }
    connection
      .prepare(
        `INSERT INTO state_owners (
           owner_epoch, supervisor_instance_id, record_json, state, row_digest
         ) VALUES (?, ?, ?, 'active', ?)`
      )
      .run(BigInt(ownerEpoch), supervisorInstanceId, JSON.stringify(owner), owner.rowDigest);
  });
  if (fenceOutcome === undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner acquisition did not transfer the time fence');
  }
  return owner;
}

export async function publishInProcessChannel(
  store: StateStore,
  client: LocalControlChannelIdentityV1['client'] = 'cli'
): Promise<{ principalId: string; channelIdentityRef: string; channelIdentityDigest: string }> {
  const now = sampleCanonicalNow();
  const processIdentity = await currentProcessIdentity(await loadNativeStateOwner(), now);
  const processArtifact = await store.artifacts.publishCanonical(
    processIdentity,
    'cliq-platform-process-identity-v1'
  );
  const principal: LocalPrincipalIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-local-principal-identity-v1',
    stateRootIdentityRef: store.stateRootIdentity.ref,
    stateRootIdentityDigest: store.stateRootIdentity.digest,
    platform: hostPlatform(),
    effectiveUid: requireEffectiveUid(),
    principalId: identityHash('cliq-local-principal-v1', store.stateRootIdentity.digest,
      processIdentity.platform, processIdentity.ownerUid),
    identityDigest: ''
  };
  principal.identityDigest = digestOmitting(principal, 'identityDigest');
  const principalArtifact = await store.artifacts.publishCanonical(
    principal,
    'cliq-local-principal-identity-v1'
  );
  const channel: LocalControlChannelIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-local-control-channel-identity-v1',
    principalIdentityRef: principalArtifact.ref,
    principalIdentityDigest: principal.identityDigest,
    principalId: principal.principalId,
    client,
    transport: {
      kind: 'in_process',
      processIdentityRef: processArtifact.ref,
      processIdentityDigest: processIdentity.identityDigest
    },
    openedAt: now,
    channelNonceDigest: sha256Bytes(randomBytes(32)),
    channelIdentityDigest: ''
  };
  channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
  const channelArtifact = await store.artifacts.publishCanonical(channel, 'cliq-local-control-channel-identity-v1');
  return { principalId: principal.principalId, channelIdentityRef: channelArtifact.ref,
    channelIdentityDigest: channel.channelIdentityDigest };
}
