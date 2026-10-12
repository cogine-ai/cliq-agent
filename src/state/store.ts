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
  type CredentialAuthorityCommandCoreV1, type CredentialAuthorityOperationV1, type CredentialPurpose,
  type EndpointAuthorityCommandCoreV1, type EndpointAuthorityOperationV1, type EndpointAuthorityRecordV1,
  type EndpointRegistrationV1, type CredentialAuthorityRecordV1 } from '../kernel/credential-authority.js';
import {
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
  type SecretServiceObservation, type SecretServiceSelector } from './credential-platform.js';
import { ensureInstalledCredentialSupervisor, type CredentialFinalizeRequest } from './installed-credential-client.js';
import { ContentAddressedStore } from './cas.js';
import { openLocalControlListener, type AuthenticatedControlIdentity, type LocalControlConnection, type LocalControlListener } from './control-channel.js';
import { readControl, type ReadControlRequest } from './control-read.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertInstalledCredentialScope, installedCredentialProvenance,
  type InstalledCredentialScope, type InstalledCredentialProvenance,
  withHeldInstalledRuntime, withInstalledWorkerRoot, type HeldInstalledAnchor,
  type HeldInstalledRuntime, type InstalledRuntimeBorrow } from './installed-runtime.js';
import { withCredentialAuthorityLock, loadInstalledCredentialPlatform } from './installed-runtime.js';
import type { SupervisorHelloV1, SupervisorStatusV1 } from './installed-control.js';
import { assertStateOwnerLock, loadNativeStateOwner, stateRootIdentityFromDescriptor, type HeldStateOwnerLock, type NativeStateOwner } from './native-owner.js';
import {
  decodeControlChannel,
  decodeLocalPrincipalIdentity,
  decodePlatformProcessIdentity,
  decodeStateLockIdentity,
  decodeStateOwnerAcquisitionEvidence,
  decodeStateOwnerTransitionEvidence,
  decodeStateRootIdentity
} from './decoders.js';
import { admitRun, type AdmitRunInput, type AdmitRunResult } from './reducers/admission.js';
import { loadAgentRun, type LoadAgentRunInput } from './reducers/agent.js';
import {
  abandonUnknownInvocation,
  claimInvocationDispatch,
  completeInvocation,
  failClaimedInvocationWithoutRelease,
  failInvocationBeforeDispatch,
  markInvocationUnknown,
  prepareInvocation,
  type ClaimInvocationDispatchInput,
  type PrepareInvocationInput,
  type SettleInvocationInput
} from './reducers/invocation.js';
import { createSession, type CreateSessionInput, type CreateSessionResult } from './reducers/session.js';
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
import { readRecoveryClosure } from './recovery-closure.js';
import { beginWorkerRecovery, beginWorkerRecoveryProbe, closeWorkerRecoveryProbe, type BeginWorkerRecoveryInput } from './reducers/worker-recovery.js';
import { readRun, readSession } from './rows.js';
import { applyKernelSchema, assertPristineKernelSchema, KERNEL_SCHEMA_SQL, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import {
  assertActiveStateOwner,
  assertContiguousStateOwnerHistory,
  contextFromStateOwner,
  gracefullyReleaseStateOwner,
  readActiveStateOwner,
  readLatestStateOwner,
  readStateOwner,
  insertStateOwnerArtifacts,
  terminalStateOwnerRecord,
  type StateOwnerContext
} from './state-owner.js';
import { hostPlatform } from './workspace-identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { loadRunExecution, type LoadRunExecutionInput, type RunExecutionInstallation } from './run-execution.js';
import { retireAbandonedPreactivations } from './preactivation-retirement.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { SandboxProfileV1, SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { normalizeRunSubmitRequest, runSubmitIntentDigest } from './source-target.js';
import { assertCurrentControlFrame, validateControlChannelClosure } from './control-channel.js';

const SMALL_BYTES = 1_048_576;
const TRUST_BYTES = 16 * SMALL_BYTES;

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

export type CredentialEnrollRequest = Readonly<{ schemaVersion: 1; kind: 'enroll'; requestId: string;
  credentialGrantId: string; purpose: CredentialPurpose; endpointRegistrationId: string; secretSubmissionId: string; expiresAt?: string }>;
export function decodeCredentialEnrollRequest(input: unknown): CredentialEnrollRequest {
  const value = input as Record<string, unknown>;
  const keys = ['schemaVersion', 'kind', 'requestId', 'credentialGrantId', 'purpose', 'endpointRegistrationId', 'secretSubmissionId'];
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || value.schemaVersion !== 1 || value.kind !== 'enroll' ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string' || ![...keys, 'expiresAt'].includes(key)) ||
      keys.some(key => !Object.hasOwn(value, key))) throw new TypeError('invalid credential enrollment metadata');
  for (const key of ['requestId', 'credentialGrantId', 'endpointRegistrationId', 'secretSubmissionId']) {
    const text = value[key];
    if (typeof text !== 'string' || !text || text.includes('\0') || normalizeCanonicalText(text) !== text ||
        Buffer.byteLength(text) > (key === 'endpointRegistrationId' ? 4096 : 256)) throw new TypeError('invalid credential enrollment id');
  }
  assertRequestId(value.requestId as string);
  if (!['model_endpoint', 'dependency_registry', 'mcp_streamable_http'].includes(value.purpose as string)) throw new TypeError('invalid credential purpose');
  if (Object.hasOwn(value, 'expiresAt')) {
    if (typeof value.expiresAt !== 'string') throw new TypeError('invalid credential expiry');
    parseCanonicalTime(value.expiresAt);
  }
  return immutableSnapshot(value as CredentialEnrollRequest);
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
function retainedCredentialChannel(held: CredentialBinding, operation: CredentialAuthorityOperationV1) {
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
      parseCanonicalTime(operation.createdAt) < parseCanonicalTime(channel.openedAt) ||
      (operation.finishedAt !== undefined && parseCanonicalTime(operation.finishedAt) < parseCanonicalTime(operation.createdAt)))
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
          (prepared && !canonicalJsonBytes(prepared.commandCore).equals(canonicalJsonBytes(operation.commandCore))))
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
function readCredentialHistory(held: CredentialBinding, grantId: string, resultRevision?: number):
  { latest?: CredentialAuthorityRecordV1; result?: CredentialAuthorityRecordV1 } {
  let latest: CredentialAuthorityRecordV1 | undefined, result: CredentialAuthorityRecordV1 | undefined;
  for (const row of held.database!.prepare(`SELECT authority_revision,record_json FROM credential_records
    WHERE owner_principal_id=? AND credential_grant_id=? ORDER BY authority_revision`).iterate(held.ownerPrincipalId, grantId)) {
    const record = endpointJson(row.record_json, decodeCredentialAuthorityRecord);
    if (record.ownerPrincipalId !== held.ownerPrincipalId || record.credentialGrantId !== grantId ||
        record.authorityRevision !== (latest?.authorityRevision ?? 0) + 1 || row.authority_revision !== record.authorityRevision ||
        record.state !== 'active' || latest?.state === 'revoked' || record.credentialServiceRevision !== 1 ||
        record.secretGeneration !== (latest?.secretGeneration ?? 0) + 1 ||
        (latest && (record.credentialHandleIdentityDigest !== latest.credentialHandleIdentityDigest ||
          parseCanonicalTime(record.createdAt) < parseCanonicalTime(latest.createdAt))))
      throw new TypeError('credential authority history is not contiguous');
    const operation = credentialCreatingOperation(held, record);
    if (operation.kind !== (latest ? 'rotate' : 'enroll') ||
        (record.expiresAt && parseCanonicalTime(record.expiresAt) <= parseCanonicalTime(record.createdAt)))
      throw new TypeError('credential result kind or expiry differs');
    latest = record;
    if (record.authorityRevision === resultRevision) result = record;
  }
  if (!latest && held.database!.prepare(`SELECT 1 FROM credential_operation_facts WHERE owner_principal_id=?
    AND credential_grant_id=? AND phase_rank=2 AND json_extract(operation_json,'$.phase')='committed' LIMIT 1`).get(held.ownerPrincipalId, grantId))
    throw new TypeError('credential committed operation has no authority result');
  return { latest, result };
}
function checkCredentialReplay(held: CredentialBinding, request: CredentialEnrollRequest): CredentialAuthorityOperationV1 | undefined {
  ensureEndpointSchema(held.database!);
  if (credentialSchemaVersion(held.database!) === 1) return undefined;
  if (held.database!.prepare('SELECT 1 FROM credential_revoke_operations WHERE owner_principal_id=? AND request_id=?').get(held.ownerPrincipalId, request.requestId))
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential request already belongs to revocation');
  const facts = readCredentialFacts(held, request.requestId), operation = facts.at(-1)?.operation;
  if (!operation) return undefined;
  const core = operation.commandCore, endpoint = credentialEndpoint(held, core);
  if (core.kind !== request.kind || core.credentialGrantId !== request.credentialGrantId || core.purpose !== request.purpose ||
      endpoint.endpointRegistrationId !== request.endpointRegistrationId || core.secretSubmissionId !== request.secretSubmissionId || core.expiresAt !== request.expiresAt)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'credential request already names different intent');
  if (operation.phase === 'committed') {
    const history = readCredentialHistory(held, operation.credentialGrantId, operation.committedAuthorityRevision);
    if (!history.result) throw new TypeError('credential replay has no historical result');
    return immutableSnapshot(operation);
  }
  // First enrollment tracer does not yet qualify recovery. A pending fact is
  // never promoted or spent by a read or a replacement producer.
  throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential request requires independent orphan recovery');
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
function commitCredentialEnrollment(held: CredentialBinding, operation: CredentialAuthorityOperationV1, now: string): CredentialAuthorityOperationV1 {
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
function prepareCredentialEnrollment(held: CredentialBinding, request: CredentialEnrollRequest): CredentialAuthorityOperationV1 {
  ensureCredentialSchema(held.database!);
  if (checkCredentialReplay(held, request)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential already committed during preparation');
  if (readCredentialHistory(held, request.credentialGrantId).latest)
    throw new KernelStorageError('REVISION_CONFLICT', 'credential id is already enrolled');
  const pending = held.database!.prepare(`SELECT 1 FROM credential_operation_facts AS f WHERE owner_principal_id=?
    AND credential_grant_id=? AND phase_rank=0 AND NOT EXISTS(SELECT 1 FROM credential_operation_facts AS t
      WHERE t.owner_principal_id=f.owner_principal_id AND t.request_id=f.request_id AND t.attempt=f.attempt AND t.phase_rank=2) LIMIT 1`)
    .get(held.ownerPrincipalId, request.credentialGrantId);
  if (pending) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential has a pending producer');
  const endpoints = readEndpointHistory(held, request.endpointRegistrationId), endpoint = endpoints.at(-1);
  if (!endpoint || endpoint.state !== 'active' || !endpoint.registration.purposes.includes(request.purpose))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential requires a current active endpoint of its purpose');
  const now = sampleCanonicalNow();
  if (parseCanonicalTime(now) < parseCanonicalTime(endpoint.createdAt) || parseCanonicalTime(now) < parseCanonicalTime(held.channelIdentity.openedAt) ||
      (request.expiresAt && parseCanonicalTime(request.expiresAt) <= parseCanonicalTime(now)))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential preparation time or expiry is invalid');
  const subjectBody = { schemaVersion: 1 as const, format: 'cliq-credential-external-subject-v1' as const,
    endpointIdentityDigest: endpoint.registration.endpointIdentityDigest,
    subject: { kind: 'opaque_generation' as const, opaqueSubjectId: randomBytes(32).toString('base64url'),
      scopes: ['endpoint_exact_only'] as ['endpoint_exact_only'], audiences: [] as [] }, observedAt: now };
  const externalSubject = { ...subjectBody, subjectDigest: canonicalSha256(subjectBody) };
  const target = { credentialGrantId: request.credentialGrantId, ownerPrincipalId: held.ownerPrincipalId, purpose: request.purpose,
    endpointRegistrationRef: endpoint.expectedRegistrationArtifactRef, endpointIdentityDigest: endpoint.registration.endpointIdentityDigest,
    tlsPolicyDigest: endpoint.registration.tlsPolicyDigest, ...(request.expiresAt ? { expiresAt: request.expiresAt } : {}),
    externalSubjectDigest: externalSubject.subjectDigest };
  const coreBody = { schemaVersion: 1 as const, ...target, kind: request.kind, secretSubmissionId: request.secretSubmissionId,
    externalSubject, credentialTargetDigest: canonicalSha256(target) };
  const core = decodeCredentialAuthorityCommandCore({ ...coreBody, commandDigest: canonicalSha256(coreBody) });
  const operationBody = { schemaVersion: 1 as const, operationId: identityHash(held.ownerPrincipalId, request.requestId, core.commandDigest, 1),
    requestId: request.requestId, requestDigest: core.commandDigest, channelIdentityRef: canonicalSha256(held.channelIdentity),
    channelIdentityDigest: held.channelIdentity.channelIdentityDigest, commandCore: core, attempt: 1 as const, ownerPrincipalId: held.ownerPrincipalId,
    kind: core.kind, credentialGrantId: core.credentialGrantId, credentialTargetDigest: core.credentialTargetDigest,
    intendedAuthorityRevision: 1, intendedSecretGeneration: 1, intendedExternalSubjectDigest: core.externalSubjectDigest,
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
  fields: { committedAuthorityRevision?: number; abortReason?: 'platform_store_failed'; finishedAt?: string } = {}): CredentialAuthorityOperationV1 {
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
export async function enrollCredentialAuthority(selected: HeldInstalledRuntime, request: CredentialEnrollRequest): Promise<CredentialAuthorityOperationV1> {
  const replay = await withCredentialAuthorityLock(selected, async token => {
    const held = checkedCredentialToken(token); request = decodeCredentialEnrollRequest(request);
    return checkCredentialReplay(held, request);
  });
  if (replay) return replay;
  let client = await ensureInstalledCredentialSupervisor(selected);
  let secret: Buffer | undefined;
  try {
    secret = await readCredentialSecret();
    // Input waited without credential locks. Reconnect/observe the actual
    // current owner before preparation instead of reusing old readiness.
    await client.close(); client = await ensureInstalledCredentialSupervisor(selected);
    const platform = await loadInstalledCredentialPlatform(selected);
    const operation = await withCredentialAuthorityLock(selected, async token => {
      const held = checkedCredentialToken(token), raced = checkCredentialReplay(held, request);
      if (raced) return raced;
      const prepared = prepareCredentialEnrollment(held, request);
      let observation: SecretServiceObservation;
      try {
        observation = decodeSecretServiceObservation(await platform.secretService({ kind: 'create_compare',
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
    return await client.finalize({ protocolVersion: 1, method: 'credential.finalize', requestId: operation.requestId,
      operationId: operation.operationId, attempt: operation.attempt, commandDigest: operation.requestDigest });
  } finally { secret?.fill(0); await client.close(); }
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
  const names = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(row => row.name).sort();
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

const AUTHORITY_TABLES = [
  'canonical_time_fence',
  'state_owners',
  'artifacts',
  'sessions',
  'items',
  'runs',
  'checkpoints',
  'run_journal',
  'run_events',
  'worker_launches',
  'workspace_generations',
  'local_inference_activation_cycles',
  'local_inference_launches',
  'control_requests',
  'list_read_cuts',
  'list_read_cut_entries',
  'child_allocations',
  'authorization_grants',
  'source_inspection_attempts',
  'mcp_registrations',
  'admin_operations'
] as const;

function assertFreshAuthorityDatabaseEmpty(connection: SqliteConnection | SqliteDriver): void {
  for (const table of AUTHORITY_TABLES) {
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

async function readStateOwnerProcess(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1): Promise<PlatformProcessIdentityV1> {
  const processIdentity = decodePlatformProcessIdentity(
    await artifacts.readCanonical(owner.processIdentityRef)
  );
  const acquisition = decodeStateOwnerAcquisitionEvidence(
    await artifacts.readCanonical(owner.acquisitionEvidenceRef)
  );
  if (
    processIdentity.identityDigest !== owner.processIdentityDigest ||
    processIdentity.executableImageDigest !== owner.supervisorExecutableDigest ||
    processIdentity.ownerUid !== requireEffectiveUid() ||
    processIdentity.platform !== hostPlatform() ||
    processIdentity.observedAt !== owner.acquiredAt ||
    acquisition.evidenceDigest !== owner.acquisitionEvidenceDigest ||
    acquisition.ownerEpoch !== owner.ownerEpoch ||
    acquisition.supervisorInstanceId !== owner.supervisorInstanceId ||
    acquisition.runtimeBundleRef !== owner.runtimeBundleRef ||
    acquisition.runtimeBundleManifestDigest !== owner.runtimeBundleManifestDigest ||
    acquisition.processIdentityRef !== owner.processIdentityRef ||
    acquisition.processIdentityDigest !== owner.processIdentityDigest ||
    acquisition.stateLockIdentityRef !== owner.stateLockIdentityRef ||
    acquisition.stateLockIdentityDigest !== owner.stateLockIdentityDigest ||
    acquisition.instanceNonceDigest !== owner.instanceNonceDigest ||
    acquisition.acquiredAt !== owner.acquiredAt ||
    (owner.ownerEpoch === 1
      ? acquisition.kind !== 'genesis'
      : acquisition.kind === 'genesis' || acquisition.priorOwnerEpoch !== owner.ownerEpoch - 1)
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner process/acquisition closure does not match');
  }
  return processIdentity;
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
  active: boolean; task?: Promise<CredentialAuthorityOperationV1>; retirementFailure?: ResourceRetirementError };
const installedCredentialFinalizers = new WeakMap<StateStore, InstalledCredentialFinalizer>();

export class StateStore {
  private closed = false;
  private released = false;
  private closeRequested = false;
  private closing: Promise<void> | undefined;
  private readonly controlListeners = new Set<LocalControlListener>();
  // Reserve the Run through validation and join that opening during shutdown.
  // This protects resources; SQLite remains the sole lifecycle authority.
  private readonly executions = new Map<string, Promise<Awaited<ReturnType<typeof loadRunExecution>>>>();
  private readonly sourceInspectionTasks = new Set<SourceInspectionTask>();
  private readonly sourceInspections = new Map<string, { intent: string; task: SourceInspectionTask }>();

  private constructor(
    readonly stateRoot: string,
    private readonly driver: SqliteDriver,
    readonly artifacts: ArtifactCatalog,
    private readonly owner: StateOwnerContext,
    private readonly runtimeAuthority?: StateStoreRuntimeAuthority,
    private readonly installedRuntime?: HeldInstalledRuntime,
    private readonly installedAnchor?: HeldInstalledAnchor
  ) {}

  get ownerEpoch(): number {
    return this.owner.ownerEpoch;
  }
  supportsCredentialFinalization(): boolean { return installedCredentialFinalizers.has(this); }

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
        const fresh = decodeSecretServiceObservation(await platform.secretService({ kind: 'inspect',
          selector: credentialSelector(held, operation), expectedObservation: expected }));
        const observationBody = (value: SecretServiceObservation) => {
          const { kind: _kind, observationDigest: _digest, ...body } = value; return body;
        };
        if (fresh.kind !== 'present' || !canonicalJsonBytes(observationBody(fresh)).equals(canonicalJsonBytes(observationBody(expected))))
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential platform owner/alias/item changed');
        token.assertHeld();
        const core = operation.commandCore, registration = credentialEndpoint(held, core);
        const endpoint = readEndpointHistory(held, registration.endpointRegistrationId).at(-1);
        if (!endpoint || endpoint.state !== 'active' || endpoint.expectedRegistrationArtifactRef !== core.endpointRegistrationRef ||
            core.kind !== 'enroll' || readCredentialHistory(held, operation.credentialGrantId).latest)
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential endpoint or enrollment revision changed');
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
        if ([endpoint.createdAt, registration.createdAt, operation.createdAt, core.externalSubject.observedAt,
          original.channel.openedAt, cut.channelOpenedAt].some(time => parseCanonicalTime(time) > nowMs) ||
            (core.expiresAt && parseCanonicalTime(core.expiresAt) <= nowMs))
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'credential expansion time or expiry is not causal');
        return commitCredentialEnrollment(held, operation, cut.now);
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
    return withHeldInstalledRuntime(this.installedRuntime, async installed => {
      await assertInstalledRootBinding(this.stateRoot, this.owner.filesystem, installed);
      await validateControlChannelClosure(this.artifacts, this.owner, authenticated);
      const cut = this.driver.readSnapshot(connection => {
        try {
          const owner = assertActiveStateOwner(connection, this.owner);
          if (owner.runtimeBundleRef !== installed.bundleDigest ||
              owner.runtimeBundleManifestDigest !== installed.bundle.manifestDigest)
            throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed inventory differs from the active signed owner');
          const counts = connection.prepare(`SELECT
            COALESCE(SUM(status = 'queued'), 0) AS queued,
            COALESCE(SUM(status = 'running'), 0) AS running,
            COALESCE(SUM(status IN ('queued', 'running', 'waiting')), 0) AS nonterminal
            FROM runs`).get<{ queued: unknown; running: unknown; nonterminal: unknown }>()!;
          // Real installed admission/upgrade composition is not yet available.
          // Do not infer pin compatibility from mutable rows or advertise an
          // unverified zero count once nonterminal pins actually exist.
          if (requiredSafeInteger(counts.nonterminal, 'nonterminal Run count') !== 0)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Supervisor status requires trusted nonterminal pin observation');
          return { supervisorInstanceId: owner.supervisorInstanceId,
            stateSchemaVersion: readSchemaUserVersion(connection),
            queuedRuns: requiredSafeInteger(counts.queued, 'queued Run count'),
            runningRuns: requiredSafeInteger(counts.running, 'running Run count') };
        } catch (cause) {
          if (cause instanceof TypeError || cause instanceof SyntaxError)
            throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained Supervisor status metadata is invalid', { cause });
          throw cause;
        }
      });
      await assertInstalledRootBinding(this.stateRoot, this.owner.filesystem, installed);
      await validateControlChannelClosure(this.artifacts, this.owner, authenticated);
      assertActiveStateOwner(this.driver, this.owner);
      const summary = { schemaVersion: 1 as const, runtimeBundleRef: installed.bundleDigest,
        bundleDigest: installed.bundleDigest, bundleVersion: installed.bundle.bundleVersion };
      return immutableSnapshot({ method: 'supervisor.status' as const, health: 'degraded' as const,
        supervisorInstanceId: cut.supervisorInstanceId,
        queue: { queuedRuns: cut.queuedRuns, runningRuns: cut.runningRuns, capacity: 0 },
        stateSchemaVersion: cut.stateSchemaVersion, activeRuntimeBundle: summary,
        installedRuntimeBundles: [summary], incompatiblePinnedRunCount: 0 });
    });
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
          releaseKeys: runtimeAuthority.releaseKeys, sandboxProfile: runtimeAuthority.sourceInspection.sandboxProfile });
      return new StateStore(stateRoot, driver, artifacts, ownerContext, runtimeAuthority, installedRuntime, installedAnchor);
    } catch (error) {
      failStateStoreOpening(heldLock, driver, error);
    }
  }

  createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    return createSession(this.driver, this.artifacts, this.owner, input);
  }

  admitRun(input: AdmitRunInput): Promise<AdmitRunResult> {
    return admitRun(this.driver, this.artifacts, this.owner, input);
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
    return loadAgentRun(this.driver, this.artifacts, this.owner, input);
  }

  async loadRunExecution(input: LoadRunExecutionInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    const runId = input.runId;
    if (this.executions.has(runId)) throw new KernelStorageError('REVISION_CONFLICT', 'Run already has an execution resource owner');
    const opening = loadRunExecution(this.driver, this.artifacts, this.owner, this.runtimeAuthority, input,
      () => this.closed || this.closeRequested || this.released, this.installedRuntime, this.installedAnchor);
    this.executions.set(runId, opening);
    let scope: Awaited<typeof opening> | undefined;
    try {
      scope = await opening;
      if (this.closed || this.closeRequested || this.released) {
        await scope.close();
        throw new KernelStorageError('LEASE_FENCED', 'StateStore closed while loading execution');
      }
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
  async captureSubmittedSource(input: CaptureSubmittedSourceInput): Promise<SourceInspectionAttemptV1> {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    input = immutableSnapshot(input);
    if (!input || Object.keys(input).length !== 2 || !Object.hasOwn(input, 'request') || !Object.hasOwn(input, 'identity')) {
      throw new KernelStorageError('INVALID_REQUEST', 'source capture requires one inline request and authenticated identity');
    }
    const normalized = normalizeRunSubmitRequest(input.request);
    const key = identityHash('cliq-source-inspection-task-v1', input.identity.principalId, normalized.request.admissionKey);
    const intent = runSubmitIntentDigest(input.identity.principalId, normalized.request);
    const existing = this.sourceInspections.get(key);
    const abort = new AbortController();
    const promise = Promise.resolve().then(async () => {
      abort.signal.throwIfAborted();
      await validateControlChannelClosure(this.artifacts, this.owner, input.identity);
      abort.signal.throwIfAborted();
      assertActiveStateOwner(this.driver, this.owner);
      const { captureSubmittedSource, assertSourceInspectionRequestId } = await import('./source-inspection-owner.js');
      assertSourceInspectionRequestId(this.driver, input.identity.principalId, normalized.request,
        existing && identityHash('cliq-source-inspection-v1', input.identity.principalId, 'run.submit', normalized.request.admissionKey, intent));
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
      return captureSubmittedSource(this.driver, this.artifacts, this.owner,
        { bundle: bootstrap.bundle, releaseKeys: bootstrap.releaseKeys, ...bootstrap.sourceInspection }, input, abort.signal);
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
    return readControl(this.driver, this.artifacts, this.owner, request, identity);
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

  close(): Promise<void> {
    if (this.closed) return Promise.resolve();
    if (this.closing !== undefined) return this.closing;
    // The gate is synchronous: existing execution references cannot dispatch
    // while listeners/opening resources are being joined.
    this.closeRequested = true;
    for (const task of this.sourceInspectionTasks) task.abort.abort();
    const attempt = (async () => {
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
      const failure = results.find(result => result.status === 'rejected');
      if (failure?.status === 'rejected') throw failure.reason;
      this.executions.clear();
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
      tables: AUTHORITY_TABLES.length
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
      runtimeBundleManifestDigest: installed.bundle.manifestDigest } : { origin: 'fresh_empty' as const }),
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

async function readStateOwnerTransition(
  artifacts: ArtifactCatalog,
  prior: Extract<StateOwnerRecordV1, { state: 'terminal' }>,
  successor?: StateOwnerRecordV1
): Promise<StateOwnerTransitionEvidenceV1> {
  const transition = decodeStateOwnerTransitionEvidence(await artifacts.readCanonical(prior.transitionEvidenceRef));
  if (transition.kind !== prior.terminalReason || transition.evidenceDigest !== prior.transitionEvidenceDigest ||
      transition.priorOwnerEpoch !== prior.ownerEpoch || transition.priorSupervisorInstanceId !== prior.supervisorInstanceId ||
      transition.priorProcessIdentityRef !== prior.processIdentityRef || transition.priorProcessIdentityDigest !== prior.processIdentityDigest ||
      transition.stateLockIdentityRef !== prior.stateLockIdentityRef || transition.stateLockIdentityDigest !== prior.stateLockIdentityDigest ||
      (transition.kind === 'graceful_release'
        ? transition.releasingProcessIdentityRef !== prior.processIdentityRef || transition.releasingProcessIdentityDigest !== prior.processIdentityDigest
        : !successor || transition.successorOwnerEpoch !== successor.ownerEpoch ||
          transition.successorSupervisorInstanceId !== successor.supervisorInstanceId ||
          transition.successorRuntimeBundleRef !== successor.runtimeBundleRef ||
          transition.successorRuntimeBundleManifestDigest !== successor.runtimeBundleManifestDigest ||
          transition.successorProcessIdentityRef !== successor.processIdentityRef ||
          transition.successorProcessIdentityDigest !== successor.processIdentityDigest ||
          transition.successorInstanceNonceDigest !== successor.instanceNonceDigest || transition.observedAt !== successor.acquiredAt)) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner transition evidence does not match its prior/successor');
  }
  return transition;
}

async function validateOwnerPredecessor(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerRecordV1): Promise<void> {
  const acquisition = decodeStateOwnerAcquisitionEvidence(await artifacts.readCanonical(owner.acquisitionEvidenceRef));
  if (acquisition.kind === 'genesis') return;
  const prior = readStateOwner(driver, acquisition.priorOwnerEpoch);
  if (!prior || prior.state !== 'terminal' || prior.rowDigest !== acquisition.priorTerminalRowDigest ||
      prior.terminalReason !== acquisition.priorTerminalReason || prior.transitionEvidenceRef !== acquisition.priorTransitionEvidenceRef ||
      prior.transitionEvidenceDigest !== acquisition.priorTransitionEvidenceDigest ||
      prior.stateLockIdentityRef !== owner.stateLockIdentityRef || prior.stateLockIdentityDigest !== owner.stateLockIdentityDigest) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner acquisition does not match its retained predecessor');
  }
  await readStateOwnerTransition(artifacts, prior, owner);
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
  const priorProcess = await readStateOwnerProcess(artifacts, prior);
  await validateOwnerPredecessor(driver, artifacts, prior);
  if (prior.state === 'terminal') await readStateOwnerTransition(artifacts, prior);

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
