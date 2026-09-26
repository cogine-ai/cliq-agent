import path from 'node:path';

import { canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import {
  assertArtifactRef,
  digestOmitting,
  normalizeAbsolutePath,
  parseCanonicalTime,
  requiredSafeInteger,
  sha256Bytes
} from '../kernel/identity.js';
import type {
  AdmittedContextManifest,
  BudgetSettlementV1,
  BudgetUsage,
  ContextManifest,
  DirectUnverifiedConsentV1,
  FrozenIgnoreRulesV1,
  LocalControlChannelIdentityV1,
  LocalPrincipalIdentityV1,
  LocalSocketPeerObservationV2,
  PlatformProcessIdentityV1,
  RepositoryIdentityV1,
  RunObjectiveV1,
  RunSpec,
  SessionContextProjection,
  SourceManifest,
  SourceProjectionSpec,
  StateLockIdentityV1,
  StateOwnerAcquisitionEvidenceV1,
  StateOwnerRecordV1,
  StateOwnerTransitionEvidenceV1,
  StateRootIdentityV1,
  VerifierSpec,
  WorkerIdentity,
  WorkspaceEntryManifest,
  WorkspaceGenerationIdentityV1,
  WorkspaceGenerationSnapshotEvidenceV1,
  WorkspaceIdentityV1,
  WorkspaceStateManifest
} from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be a nonempty string`);
  }
  return value;
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string
): void {
  const allowedKeys = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `${label}.${key} is not part of the closed schema`);
    }
  }
}

function requireSafeInteger(value: unknown, label: string, minimum = 0): number {
  let parsed: number;
  try {
    parsed = requiredSafeInteger(value, label);
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be a safe integer`);
  }
  if (parsed < minimum) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be at least ${minimum}`);
  }
  return parsed;
}

function requireArtifactRef(value: unknown, label: string): string {
  const ref = requireString(value, label);
  try {
    assertArtifactRef(ref);
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be a canonical ArtifactRef`);
  }
  return ref;
}

function requireCanonicalTime(value: unknown, label: string): string {
  const timestamp = requireString(value, label);
  try {
    parseCanonicalTime(timestamp);
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be a canonical UTC millisecond`);
  }
  return timestamp;
}

function requireUnsignedDecimal(value: unknown, label: string): string {
  const decimal = requireString(value, label);
  if (!/^(?:0|[1-9]\d*)$/u.test(decimal)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be an unsigned decimal string`);
  }
  return decimal;
}

function requireDigest(value: unknown, label: string): string {
  return requireArtifactRef(value, label);
}

function requireRootRelativePath(value: unknown, label: string): string {
  const text = requireString(value, label);
  let normalized: string;
  try {
    normalized = normalizeCanonicalText(text);
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} has invalid Unicode`);
  }
  const components = text.split('/');
  if (normalized !== text || text.includes('\\') || Buffer.byteLength(text, 'utf8') > 4096 ||
      components.some((component) => component === '' || component === '.' || component === '..' ||
        component === '.git' || Buffer.byteLength(component, 'utf8') > 255)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} is not a canonical in-root path`);
  }
  return text;
}

function requirePlatform(value: unknown, label: string): 'linux' | 'macos' {
  if (value !== 'linux' && value !== 'macos') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be linux or macos`);
  }
  return value;
}

function requireFilesystemIdentity(value: unknown, label: string): void {
  if (!isRecord(value) || Object.keys(value).length !== 3 ||
      !['deviceId', 'fileId', 'ownerUid'].every((key) => Object.hasOwn(value, key))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} has an invalid closed shape`);
  }
  for (const key of ['deviceId', 'fileId'] as const) {
    const id = requireUnsignedDecimal(value[key], `${label}.${key}`);
    if (id.length > 20 || BigInt(id) > 18_446_744_073_709_551_615n) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `${label}.${key} exceeds an unsigned 64-bit id`);
    }
  }
  requireSafeInteger(value.ownerUid, `${label}.ownerUid`);
}

export function decodeRepositoryIdentity(value: unknown): RepositoryIdentityV1 {
  if (!isRecord(value) || value.format !== 'cliq-repository-identity-v1' || value.schemaVersion !== 1 ||
      Object.keys(value).length !== 7 || !['schemaVersion', 'format', 'platform',
        'gitDirectoryRelativePath', 'gitDirectoryIdentity', 'objectFormat',
        'repositoryIdentityDigest'].every((key) => Object.hasOwn(value, key))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'repository identity has an invalid closed shape');
  }
  requirePlatform(value.platform, 'RepositoryIdentity.platform');
  if (value.gitDirectoryRelativePath !== '.git' ||
      (value.objectFormat !== 'sha1' && value.objectFormat !== 'sha256')) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'repository identity has an invalid Git identity');
  }
  requireFilesystemIdentity(value.gitDirectoryIdentity, 'RepositoryIdentity.gitDirectoryIdentity');
  requireDigest(value.repositoryIdentityDigest, 'RepositoryIdentity.repositoryIdentityDigest');
  const identity = value as RepositoryIdentityV1;
  if (digestOmitting(identity, 'repositoryIdentityDigest') !== identity.repositoryIdentityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'repository identity digest does not rehash');
  }
  return identity;
}

export function decodeWorkspaceIdentity(value: unknown): WorkspaceIdentityV1 {
  if (!isRecord(value) || value.format !== 'cliq-workspace-identity-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace identity has the wrong schema');
  }
  if (value.kind === 'legacy_unavailable') {
    throw new KernelStorageError('INVALID_REQUEST', 'legacy_unavailable Sessions cannot admit a Run');
  }
  if (value.kind !== 'live') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace identity kind is invalid');
  }
  const git = Object.hasOwn(value, 'repositoryIdentityRef') || Object.hasOwn(value, 'repositoryIdentityDigest');
  const keys = ['schemaVersion', 'format', 'ownerPrincipalId', 'platform', 'kind',
    'canonicalRootPath', 'rootIdentity', 'identityDigest',
    ...(git ? ['repositoryIdentityRef', 'repositoryIdentityDigest'] : [])];
  if (Object.keys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace identity has an invalid closed shape');
  }
  requireString(value.ownerPrincipalId, 'WorkspaceIdentity.ownerPrincipalId');
  requirePlatform(value.platform, 'WorkspaceIdentity.platform');
  requireFilesystemIdentity(value.rootIdentity, 'WorkspaceIdentity.rootIdentity');
  if (typeof value.canonicalRootPath !== 'string') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace path is not canonical');
  }
  try {
    if (normalizeAbsolutePath(value.canonicalRootPath) !== value.canonicalRootPath) throw new Error('noncanonical');
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace path is not canonical');
  }
  if (git) {
    requireArtifactRef(value.repositoryIdentityRef, 'WorkspaceIdentity.repositoryIdentityRef');
    requireDigest(value.repositoryIdentityDigest, 'WorkspaceIdentity.repositoryIdentityDigest');
  }
  requireDigest(value.identityDigest, 'WorkspaceIdentity.identityDigest');
  const identity = value as WorkspaceIdentityV1;
  if (digestOmitting(identity, 'identityDigest') !== identity.identityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace identity digest does not rehash');
  }
  return identity;
}

export function decodeSessionProjection(value: unknown): SessionContextProjection {
  if (!isRecord(value) || value.format !== 'cliq-session-context-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'session projection has the wrong schema');
  }
  const projection = value as SessionContextProjection;
  if (digestOmitting(projection, 'projectionDigest') !== projection.projectionDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'session projection digest does not rehash');
  }
  return projection;
}

export function decodeControlChannel(value: unknown): LocalControlChannelIdentityV1 {
  if (!isRecord(value) || value.format !== 'cliq-local-control-channel-identity-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel identity has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion',
      'format',
      'principalIdentityRef',
      'principalIdentityDigest',
      'principalId',
      'client',
      'transport',
      'openedAt',
      'channelNonceDigest',
      'channelIdentityDigest'
    ],
    'LocalControlChannelIdentity'
  );
  requireArtifactRef(value.principalIdentityRef, 'LocalControlChannelIdentity.principalIdentityRef');
  requireDigest(value.principalIdentityDigest, 'LocalControlChannelIdentity.principalIdentityDigest');
  requireString(value.principalId, 'LocalControlChannelIdentity.principalId');
  if (!['cli', 'tui', 'jsonl', 'rpc'].includes(String(value.client))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel client is invalid');
  }
  if (!isRecord(value.transport)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel transport must be an object');
  }
  if (value.transport.kind === 'in_process') {
    rejectUnknownKeys(
      value.transport,
      ['kind', 'processIdentityRef', 'processIdentityDigest'],
      'LocalControlChannelIdentity.transport'
    );
    requireArtifactRef(value.transport.processIdentityRef, 'control channel processIdentityRef');
    requireDigest(value.transport.processIdentityDigest, 'control channel processIdentityDigest');
  } else if (value.transport.kind === 'uds_peer') {
    rejectUnknownKeys(
      value.transport,
      ['kind', 'peerObservationRef', 'peerObservationDigest'],
      'LocalControlChannelIdentity.transport'
    );
    requireArtifactRef(value.transport.peerObservationRef, 'control channel peerObservationRef');
    requireDigest(value.transport.peerObservationDigest, 'control channel peerObservationDigest');
  } else {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel transport is invalid');
  }
  requireCanonicalTime(value.openedAt, 'LocalControlChannelIdentity.openedAt');
  requireDigest(value.channelNonceDigest, 'LocalControlChannelIdentity.channelNonceDigest');
  requireDigest(value.channelIdentityDigest, 'LocalControlChannelIdentity.channelIdentityDigest');
  const channel = value as LocalControlChannelIdentityV1;
  if (digestOmitting(channel, 'channelIdentityDigest') !== channel.channelIdentityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel digest does not rehash');
  }
  return channel;
}

export function decodeLocalPrincipalIdentity(value: unknown): LocalPrincipalIdentityV1 {
  if (
    !isRecord(value) ||
    value.format !== 'cliq-local-principal-identity-v1' ||
    value.schemaVersion !== 1
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'local principal identity has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion',
      'format',
      'stateRootIdentityRef',
      'stateRootIdentityDigest',
      'platform',
      'effectiveUid',
      'principalId',
      'identityDigest'
    ],
    'LocalPrincipalIdentity'
  );
  requireArtifactRef(value.stateRootIdentityRef, 'LocalPrincipalIdentity.stateRootIdentityRef');
  requireDigest(value.stateRootIdentityDigest, 'LocalPrincipalIdentity.stateRootIdentityDigest');
  requirePlatform(value.platform, 'LocalPrincipalIdentity.platform');
  requireSafeInteger(value.effectiveUid, 'LocalPrincipalIdentity.effectiveUid');
  requireString(value.principalId, 'LocalPrincipalIdentity.principalId');
  requireDigest(value.identityDigest, 'LocalPrincipalIdentity.identityDigest');
  const identity = value as LocalPrincipalIdentityV1;
  if (digestOmitting(identity, 'identityDigest') !== identity.identityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'local principal identity digest does not rehash');
  }
  return identity;
}

/** Closed historical evidence decoder. This function never grants live UDS authority. */
export function decodeLocalSocketPeerObservation(value: unknown): LocalSocketPeerObservationV2 {
  if (!isRecord(value) || value.format !== 'cliq-local-socket-peer-observation-v2' || value.schemaVersion !== 2) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'socket peer observation has the wrong schema');
  }
  rejectUnknownKeys(value, [
    'schemaVersion', 'format', 'platform', 'stateRootIdentityRef', 'stateRootIdentityDigest',
    'endpoint', 'listenerSocket', 'acceptedSocket', 'credentialApi', 'peerUid', 'peerGid',
    'observedAt', 'observationDigest'
  ], 'LocalSocketPeerObservationV2');
  const platform = requirePlatform(value.platform, 'LocalSocketPeerObservationV2.platform');
  requireArtifactRef(value.stateRootIdentityRef, 'LocalSocketPeerObservationV2.stateRootIdentityRef');
  requireDigest(value.stateRootIdentityDigest, 'LocalSocketPeerObservationV2.stateRootIdentityDigest');
  if (!isRecord(value.endpoint)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'socket endpoint identity is missing');
  }
  rejectUnknownKeys(value.endpoint, [
    'canonicalRootRelativePath', 'fileType', 'deviceId', 'fileId', 'ownerUid', 'mode'
  ], 'LocalSocketPeerObservationV2.endpoint');
  if (value.endpoint.canonicalRootRelativePath !== 'runtime/control-v1.sock' ||
      value.endpoint.fileType !== 'unix_stream_socket' || value.endpoint.mode !== 384) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'socket endpoint identity is invalid');
  }
  requireUnsignedDecimal(value.endpoint.deviceId, 'LocalSocketPeerObservationV2.endpoint.deviceId');
  requireUnsignedDecimal(value.endpoint.fileId, 'LocalSocketPeerObservationV2.endpoint.fileId');
  requireSafeInteger(value.endpoint.ownerUid, 'LocalSocketPeerObservationV2.endpoint.ownerUid');
  for (const member of ['listenerSocket', 'acceptedSocket'] as const) {
    const socket = value[member];
    if (!isRecord(socket)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `${member} identity is missing`);
    }
    rejectUnknownKeys(socket, ['socketFamily', 'socketType', 'deviceId', 'fileId'], `LocalSocketPeerObservationV2.${member}`);
    if (socket.socketFamily !== 'AF_UNIX' || socket.socketType !== 'SOCK_STREAM') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `${member} is not a Unix stream socket`);
    }
    requireUnsignedDecimal(socket.deviceId, `LocalSocketPeerObservationV2.${member}.deviceId`);
    requireUnsignedDecimal(socket.fileId, `LocalSocketPeerObservationV2.${member}.fileId`);
  }
  if (value.credentialApi !== (platform === 'macos' ? 'macos_getpeereid' : 'linux_so_peercred')) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'socket peer credential API is invalid');
  }
  requireSafeInteger(value.peerUid, 'LocalSocketPeerObservationV2.peerUid');
  requireSafeInteger(value.peerGid, 'LocalSocketPeerObservationV2.peerGid');
  requireCanonicalTime(value.observedAt, 'LocalSocketPeerObservationV2.observedAt');
  requireDigest(value.observationDigest, 'LocalSocketPeerObservationV2.observationDigest');
  const observation = value as LocalSocketPeerObservationV2;
  if (digestOmitting(observation, 'observationDigest') !== observation.observationDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'socket peer observation digest does not rehash');
  }
  return observation;
}

export function decodePlatformProcessIdentity(value: unknown): PlatformProcessIdentityV1 {
  if (
    !isRecord(value) ||
    value.format !== 'cliq-platform-process-identity-v1' ||
    value.schemaVersion !== 1
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'platform process identity has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion',
      'format',
      'platform',
      'pid',
      'processStartToken',
      'ownerUid',
      'executableImageDigest',
      'observedAt',
      'identityDigest'
    ],
    'PlatformProcessIdentity'
  );
  requirePlatform(value.platform, 'PlatformProcessIdentity.platform');
  requireSafeInteger(value.pid, 'PlatformProcessIdentity.pid', 1);
  requireString(value.processStartToken, 'PlatformProcessIdentity.processStartToken');
  requireSafeInteger(value.ownerUid, 'PlatformProcessIdentity.ownerUid');
  requireDigest(value.executableImageDigest, 'PlatformProcessIdentity.executableImageDigest');
  requireCanonicalTime(value.observedAt, 'PlatformProcessIdentity.observedAt');
  requireDigest(value.identityDigest, 'PlatformProcessIdentity.identityDigest');
  const identity = value as PlatformProcessIdentityV1;
  if (digestOmitting(identity, 'identityDigest') !== identity.identityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'platform process identity digest does not rehash');
  }
  return identity;
}

export function decodeStateRootIdentity(value: unknown): StateRootIdentityV1 {
  if (!isRecord(value) || value.format !== 'cliq-state-root-identity-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state root identity has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion',
      'format',
      'platform',
      'canonicalAbsolutePath',
      'ownerUid',
      'deviceId',
      'directoryFileId',
      'mode',
      'openedNoFollow',
      'layoutVersion',
      'identityDigest'
    ],
    'StateRootIdentity'
  );
  requirePlatform(value.platform, 'StateRootIdentity.platform');
  const absolutePath = requireString(value.canonicalAbsolutePath, 'StateRootIdentity.canonicalAbsolutePath');
  if (!absolutePath.startsWith('/')) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state root identity path must be absolute');
  }
  requireSafeInteger(value.ownerUid, 'StateRootIdentity.ownerUid');
  requireUnsignedDecimal(value.deviceId, 'StateRootIdentity.deviceId');
  requireUnsignedDecimal(value.directoryFileId, 'StateRootIdentity.directoryFileId');
  if (value.mode !== 448 || value.openedNoFollow !== true || value.layoutVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state root identity protection fields are invalid');
  }
  requireDigest(value.identityDigest, 'StateRootIdentity.identityDigest');
  const identity = value as StateRootIdentityV1;
  if (digestOmitting(identity, 'identityDigest') !== identity.identityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state root identity digest does not rehash');
  }
  return identity;
}

export function decodeStateLockIdentity(value: unknown): StateLockIdentityV1 {
  if (!isRecord(value) || value.format !== 'cliq-state-lock-identity-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state lock identity has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion',
      'format',
      'stateRootIdentityRef',
      'stateRootIdentityDigest',
      'canonicalRootRelativePath',
      'deviceId',
      'fileId',
      'ownerUid',
      'mode',
      'linkCount',
      'identityDigest'
    ],
    'StateLockIdentity'
  );
  requireArtifactRef(value.stateRootIdentityRef, 'StateLockIdentity.stateRootIdentityRef');
  requireDigest(value.stateRootIdentityDigest, 'StateLockIdentity.stateRootIdentityDigest');
  if (value.canonicalRootRelativePath !== 'runtime/state-owner.lock') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state lock identity has the wrong relative path');
  }
  requireUnsignedDecimal(value.deviceId, 'StateLockIdentity.deviceId');
  requireUnsignedDecimal(value.fileId, 'StateLockIdentity.fileId');
  requireSafeInteger(value.ownerUid, 'StateLockIdentity.ownerUid');
  if (value.mode !== 384 || value.linkCount !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state lock identity protection fields are invalid');
  }
  requireDigest(value.identityDigest, 'StateLockIdentity.identityDigest');
  const identity = value as StateLockIdentityV1;
  if (digestOmitting(identity, 'identityDigest') !== identity.identityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state lock identity digest does not rehash');
  }
  return identity;
}

const STATE_OWNER_COMMON_KEYS = [
  'schemaVersion',
  'ownerEpoch',
  'supervisorInstanceId',
  'runtimeBundleRef',
  'runtimeBundleManifestDigest',
  'supervisorEntryId',
  'supervisorEntryVersion',
  'supervisorExecutableDigest',
  'processIdentityRef',
  'processIdentityDigest',
  'stateLockIdentityRef',
  'stateLockIdentityDigest',
  'acquisitionEvidenceRef',
  'acquisitionEvidenceDigest',
  'instanceNonceDigest',
  'acquiredAt',
  'rowDigest',
  'state',
  'rowVersion'
] as const;

export function decodeStateOwnerRecord(value: unknown): StateOwnerRecordV1 {
  if (!isRecord(value) || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner record has the wrong schema');
  }
  if (value.state === 'active') {
    rejectUnknownKeys(value, STATE_OWNER_COMMON_KEYS, 'StateOwnerRecord(active)');
    if (value.rowVersion !== 1) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'active state owner rowVersion must be one');
    }
  } else if (value.state === 'terminal') {
    rejectUnknownKeys(
      value,
      [
        ...STATE_OWNER_COMMON_KEYS,
        'releasedAt',
        'terminalReason',
        'transitionEvidenceRef',
        'transitionEvidenceDigest'
      ],
      'StateOwnerRecord(terminal)'
    );
    if (
      value.rowVersion !== 2 ||
      (value.terminalReason !== 'graceful_release' && value.terminalReason !== 'superseded_after_owner_death')
    ) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'terminal state owner discriminator is invalid');
    }
    requireCanonicalTime(value.releasedAt, 'StateOwnerRecord.releasedAt');
    requireArtifactRef(value.transitionEvidenceRef, 'StateOwnerRecord.transitionEvidenceRef');
    requireDigest(value.transitionEvidenceDigest, 'StateOwnerRecord.transitionEvidenceDigest');
  } else {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner state is invalid');
  }
  requireSafeInteger(value.ownerEpoch, 'StateOwnerRecord.ownerEpoch', 1);
  requireString(value.supervisorInstanceId, 'StateOwnerRecord.supervisorInstanceId');
  requireArtifactRef(value.runtimeBundleRef, 'StateOwnerRecord.runtimeBundleRef');
  requireDigest(value.runtimeBundleManifestDigest, 'StateOwnerRecord.runtimeBundleManifestDigest');
  requireString(value.supervisorEntryId, 'StateOwnerRecord.supervisorEntryId');
  requireString(value.supervisorEntryVersion, 'StateOwnerRecord.supervisorEntryVersion');
  requireDigest(value.supervisorExecutableDigest, 'StateOwnerRecord.supervisorExecutableDigest');
  requireArtifactRef(value.processIdentityRef, 'StateOwnerRecord.processIdentityRef');
  requireDigest(value.processIdentityDigest, 'StateOwnerRecord.processIdentityDigest');
  requireArtifactRef(value.stateLockIdentityRef, 'StateOwnerRecord.stateLockIdentityRef');
  requireDigest(value.stateLockIdentityDigest, 'StateOwnerRecord.stateLockIdentityDigest');
  requireArtifactRef(value.acquisitionEvidenceRef, 'StateOwnerRecord.acquisitionEvidenceRef');
  requireDigest(value.acquisitionEvidenceDigest, 'StateOwnerRecord.acquisitionEvidenceDigest');
  requireDigest(value.instanceNonceDigest, 'StateOwnerRecord.instanceNonceDigest');
  requireCanonicalTime(value.acquiredAt, 'StateOwnerRecord.acquiredAt');
  requireDigest(value.rowDigest, 'StateOwnerRecord.rowDigest');
  const record = value as StateOwnerRecordV1;
  if (digestOmitting(record, 'rowDigest') !== record.rowDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner row digest does not rehash');
  }
  return record;
}

const STATE_OWNER_EVIDENCE_COMMON_KEYS = [
  'schemaVersion',
  'format',
  'ownerEpoch',
  'supervisorInstanceId',
  'runtimeBundleRef',
  'runtimeBundleManifestDigest',
  'processIdentityRef',
  'processIdentityDigest',
  'stateLockIdentityRef',
  'stateLockIdentityDigest',
  'instanceNonceDigest',
  'acquiredAt',
  'evidenceDigest',
  'kind'
] as const;

export function decodeStateOwnerAcquisitionEvidence(
  value: unknown
): StateOwnerAcquisitionEvidenceV1 {
  if (
    !isRecord(value) ||
    value.schemaVersion !== 1 ||
    value.format !== 'cliq-state-owner-acquisition-evidence-v1'
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner acquisition evidence has the wrong schema');
  }
  if (value.kind === 'genesis') {
    rejectUnknownKeys(
      value,
      [
        ...STATE_OWNER_EVIDENCE_COMMON_KEYS,
        'kernelGenerationIdentityRef',
        'kernelGenerationIdentityDigest',
        'ownerTableObservation'
      ],
      'StateOwnerAcquisitionEvidence(genesis)'
    );
    requireArtifactRef(value.kernelGenerationIdentityRef, 'StateOwnerAcquisitionEvidence.kernelGenerationIdentityRef');
    requireDigest(value.kernelGenerationIdentityDigest, 'StateOwnerAcquisitionEvidence.kernelGenerationIdentityDigest');
    if (value.ownerTableObservation !== 'empty') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'genesis owner table observation is invalid');
    }
  } else if (value.kind === 'acquire_after_graceful_release' || value.kind === 'takeover_after_owner_death') {
    rejectUnknownKeys(
      value,
      [
        ...STATE_OWNER_EVIDENCE_COMMON_KEYS,
        'priorOwnerEpoch',
        'priorTerminalRowDigest',
        'priorTransitionEvidenceRef',
        'priorTransitionEvidenceDigest',
        'priorTerminalReason'
      ],
      'StateOwnerAcquisitionEvidence(successor)'
    );
    requireSafeInteger(value.priorOwnerEpoch, 'StateOwnerAcquisitionEvidence.priorOwnerEpoch', 1);
    requireDigest(value.priorTerminalRowDigest, 'StateOwnerAcquisitionEvidence.priorTerminalRowDigest');
    requireArtifactRef(value.priorTransitionEvidenceRef, 'StateOwnerAcquisitionEvidence.priorTransitionEvidenceRef');
    requireDigest(value.priorTransitionEvidenceDigest, 'StateOwnerAcquisitionEvidence.priorTransitionEvidenceDigest');
    const expectedReason = value.kind === 'acquire_after_graceful_release'
      ? 'graceful_release'
      : 'superseded_after_owner_death';
    if (value.priorTerminalReason !== expectedReason) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner acquisition terminal reason is invalid');
    }
  } else {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner acquisition kind is invalid');
  }
  requireSafeInteger(value.ownerEpoch, 'StateOwnerAcquisitionEvidence.ownerEpoch', 1);
  requireString(value.supervisorInstanceId, 'StateOwnerAcquisitionEvidence.supervisorInstanceId');
  requireArtifactRef(value.runtimeBundleRef, 'StateOwnerAcquisitionEvidence.runtimeBundleRef');
  requireDigest(value.runtimeBundleManifestDigest, 'StateOwnerAcquisitionEvidence.runtimeBundleManifestDigest');
  requireArtifactRef(value.processIdentityRef, 'StateOwnerAcquisitionEvidence.processIdentityRef');
  requireDigest(value.processIdentityDigest, 'StateOwnerAcquisitionEvidence.processIdentityDigest');
  requireArtifactRef(value.stateLockIdentityRef, 'StateOwnerAcquisitionEvidence.stateLockIdentityRef');
  requireDigest(value.stateLockIdentityDigest, 'StateOwnerAcquisitionEvidence.stateLockIdentityDigest');
  requireDigest(value.instanceNonceDigest, 'StateOwnerAcquisitionEvidence.instanceNonceDigest');
  requireCanonicalTime(value.acquiredAt, 'StateOwnerAcquisitionEvidence.acquiredAt');
  requireDigest(value.evidenceDigest, 'StateOwnerAcquisitionEvidence.evidenceDigest');
  const evidence = value as StateOwnerAcquisitionEvidenceV1;
  if (digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner acquisition evidence does not rehash');
  }
  return evidence;
}

const STATE_OWNER_TRANSITION_COMMON_KEYS = [
  'schemaVersion',
  'format',
  'priorOwnerEpoch',
  'priorSupervisorInstanceId',
  'priorProcessIdentityRef',
  'priorProcessIdentityDigest',
  'stateLockIdentityRef',
  'stateLockIdentityDigest',
  'observedAt',
  'evidenceDigest',
  'kind'
] as const;

export function decodeStateOwnerTransitionEvidence(value: unknown): StateOwnerTransitionEvidenceV1 {
  if (
    !isRecord(value) ||
    value.schemaVersion !== 1 ||
    value.format !== 'cliq-state-owner-transition-evidence-v1'
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner transition evidence has the wrong schema');
  }
  if (value.kind === 'graceful_release') {
    rejectUnknownKeys(
      value,
      [
        ...STATE_OWNER_TRANSITION_COMMON_KEYS,
        'releasingProcessIdentityRef',
        'releasingProcessIdentityDigest'
      ],
      'StateOwnerTransitionEvidence(graceful_release)'
    );
    requireArtifactRef(value.releasingProcessIdentityRef, 'StateOwnerTransitionEvidence.releasingProcessIdentityRef');
    requireDigest(value.releasingProcessIdentityDigest, 'StateOwnerTransitionEvidence.releasingProcessIdentityDigest');
  } else if (value.kind === 'superseded_after_owner_death') {
    rejectUnknownKeys(
      value,
      [
        ...STATE_OWNER_TRANSITION_COMMON_KEYS,
        'priorProcessObservation',
        'successorOwnerEpoch',
        'successorSupervisorInstanceId',
        'successorRuntimeBundleRef',
        'successorRuntimeBundleManifestDigest',
        'successorProcessIdentityRef',
        'successorProcessIdentityDigest',
        'successorInstanceNonceDigest'
      ],
      'StateOwnerTransitionEvidence(takeover)'
    );
    if (value.priorProcessObservation !== 'absent_or_start_token_mismatch') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner takeover process observation is invalid');
    }
    requireSafeInteger(value.successorOwnerEpoch, 'StateOwnerTransitionEvidence.successorOwnerEpoch', 2);
    requireString(value.successorSupervisorInstanceId, 'StateOwnerTransitionEvidence.successorSupervisorInstanceId');
    requireArtifactRef(value.successorRuntimeBundleRef, 'StateOwnerTransitionEvidence.successorRuntimeBundleRef');
    requireDigest(value.successorRuntimeBundleManifestDigest, 'StateOwnerTransitionEvidence.successorRuntimeBundleManifestDigest');
    requireArtifactRef(value.successorProcessIdentityRef, 'StateOwnerTransitionEvidence.successorProcessIdentityRef');
    requireDigest(value.successorProcessIdentityDigest, 'StateOwnerTransitionEvidence.successorProcessIdentityDigest');
    requireDigest(value.successorInstanceNonceDigest, 'StateOwnerTransitionEvidence.successorInstanceNonceDigest');
  } else {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner transition kind is invalid');
  }
  requireSafeInteger(value.priorOwnerEpoch, 'StateOwnerTransitionEvidence.priorOwnerEpoch', 1);
  requireString(value.priorSupervisorInstanceId, 'StateOwnerTransitionEvidence.priorSupervisorInstanceId');
  requireArtifactRef(value.priorProcessIdentityRef, 'StateOwnerTransitionEvidence.priorProcessIdentityRef');
  requireDigest(value.priorProcessIdentityDigest, 'StateOwnerTransitionEvidence.priorProcessIdentityDigest');
  requireArtifactRef(value.stateLockIdentityRef, 'StateOwnerTransitionEvidence.stateLockIdentityRef');
  requireDigest(value.stateLockIdentityDigest, 'StateOwnerTransitionEvidence.stateLockIdentityDigest');
  requireCanonicalTime(value.observedAt, 'StateOwnerTransitionEvidence.observedAt');
  requireDigest(value.evidenceDigest, 'StateOwnerTransitionEvidence.evidenceDigest');
  const evidence = value as StateOwnerTransitionEvidenceV1;
  if (digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'state owner transition evidence does not rehash');
  }
  return evidence;
}

export function decodeRunObjective(value: unknown): RunObjectiveV1 {
  if (!isRecord(value) || value.format !== 'cliq-run-objective-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run objective has the wrong schema');
  }
  const objective = value as RunObjectiveV1;
  if (digestOmitting(objective, 'objectiveDigest') !== objective.objectiveDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run objective digest does not rehash');
  }
  return objective;
}

export function decodeAdmittedContext(value: unknown): AdmittedContextManifest {
  if (!isRecord(value) || value.format !== 'cliq-admitted-context-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'admitted context has the wrong schema');
  }
  const manifest = value as AdmittedContextManifest;
  if (digestOmitting(manifest, 'contextDigest') !== manifest.contextDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'admitted context digest does not rehash');
  }
  return manifest;
}

export function decodeContextManifest(value: unknown): ContextManifest {
  if (!isRecord(value) || value.format !== 'cliq-context-manifest-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run context manifest has the wrong schema');
  }
  const manifest = value as ContextManifest;
  if (digestOmitting(manifest, 'projectionDigest') !== manifest.projectionDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run context manifest digest does not rehash');
  }
  return manifest;
}

export function decodeFrozenIgnoreRules(value: unknown): FrozenIgnoreRulesV1 {
  if (!isRecord(value) || value.format !== 'cliq-frozen-ignore-rules-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules have the wrong schema');
  }
  rejectUnknownKeys(value, [
    'schemaVersion', 'format', 'matcherVersion', 'repositoryIdentityDigest',
    'sources', 'rules', 'rulesDigest'
  ], 'FrozenIgnoreRules');
  if (value.matcherVersion !== 'cliq-git-wildmatch-v1' ||
      !Array.isArray(value.sources) || !Array.isArray(value.rules)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules have an invalid matcher or arrays');
  }
  if (value.repositoryIdentityDigest !== undefined) {
    requireDigest(value.repositoryIdentityDigest, 'FrozenIgnoreRules.repositoryIdentityDigest');
  } else if (value.sources.length !== 0 || value.rules.length !== 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'non-Git frozen ignore rules must be empty');
  }
  let previousGitignore: { depth: number; path: string } | undefined;
  for (const [index, candidate] of value.sources.entries()) {
    if (!isRecord(candidate)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `frozen ignore source ${index} is invalid`);
    }
    rejectUnknownKeys(candidate, [
      'index', 'kind', 'canonicalRootRelativePath', 'baseDirectory', 'contentRef', 'contentDigest'
    ], `FrozenIgnoreRules.sources[${index}]`);
    if (candidate.index !== index) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source indices must be contiguous');
    }
    const sourcePath = candidate.canonicalRootRelativePath;
    if (candidate.kind === 'git_info_exclude') {
      if (index !== 0 || sourcePath !== '.git/info/exclude' || candidate.baseDirectory !== '') {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'Git info exclude must be the first root-bound source');
      }
    } else if (candidate.kind === 'gitignore') {
      const canonicalPath = requireRootRelativePath(sourcePath, `FrozenIgnoreRules.sources[${index}].path`);
      if (canonicalPath.split('/').at(-1) !== '.gitignore') {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source must be a .gitignore file');
      }
      const base = path.posix.dirname(canonicalPath);
      if (candidate.baseDirectory !== (base === '.' ? '' : base)) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source base directory is invalid');
      }
      const depth = canonicalPath.split('/').length;
      if (previousGitignore && (depth < previousGitignore.depth ||
          (depth === previousGitignore.depth && Buffer.compare(Buffer.from(previousGitignore.path), Buffer.from(canonicalPath)) >= 0))) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen .gitignore sources must be depth/path ordered');
      }
      previousGitignore = { depth, path: canonicalPath };
    } else {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source kind is invalid');
    }
    const contentRef = requireArtifactRef(candidate.contentRef, `FrozenIgnoreRules.sources[${index}].contentRef`);
    if (requireDigest(candidate.contentDigest, `FrozenIgnoreRules.sources[${index}].contentDigest`) !== contentRef) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source content digest differs from its CAS ref');
    }
  }
  for (const [index, candidate] of value.rules.entries()) {
    if (!isRecord(candidate)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `frozen ignore rule ${index} is invalid`);
    }
    rejectUnknownKeys(candidate, [
      'order', 'sourceIndex', 'sourceLine', 'baseDirectory', 'negated',
      'directoryOnly', 'anchored', 'pattern'
    ], `FrozenIgnoreRules.rules[${index}]`);
    const sourceIndex = requireSafeInteger(candidate.sourceIndex, `FrozenIgnoreRules.rules[${index}].sourceIndex`);
    const sourceLine = requireSafeInteger(candidate.sourceLine, `FrozenIgnoreRules.rules[${index}].sourceLine`, 1);
    const source = value.sources[sourceIndex] as Record<string, unknown> | undefined;
    if (candidate.order !== index || source === undefined ||
        candidate.baseDirectory !== source.baseDirectory ||
        typeof candidate.negated !== 'boolean' || typeof candidate.directoryOnly !== 'boolean' ||
        typeof candidate.anchored !== 'boolean') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rule order, source, or flags are invalid');
    }
    const pattern = requireString(candidate.pattern, `FrozenIgnoreRules.rules[${index}].pattern`);
    try {
      normalizeCanonicalText(pattern);
    } catch {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rule pattern is invalid text');
    }
    if (index > 0) {
      const prior = value.rules[index - 1] as Record<string, unknown>;
      if (sourceIndex < (prior.sourceIndex as number) ||
          (sourceIndex === prior.sourceIndex && sourceLine <= (prior.sourceLine as number))) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules must follow source and line order');
      }
    }
  }
  requireDigest(value.rulesDigest, 'FrozenIgnoreRules.rulesDigest');
  const rules = value as FrozenIgnoreRulesV1;
  if (digestOmitting(rules, 'rulesDigest') !== rules.rulesDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules digest does not rehash');
  }
  return rules;
}

export function decodeSourceProjection(value: unknown): SourceProjectionSpec {
  if (!isRecord(value) || value.matcherVersion !== 'cliq-exact-path-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source projection has the wrong schema');
  }
  rejectUnknownKeys(value, [
    'schemaVersion', 'matcherVersion', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest',
    'explicitIncludes', 'explicitExcludes', 'maxChangedPaths', 'maxChangedBytes', 'projectionDigest'
  ], 'SourceProjection');
  requireArtifactRef(value.frozenIgnoreRulesRef, 'SourceProjection.frozenIgnoreRulesRef');
  requireDigest(value.frozenIgnoreRulesDigest, 'SourceProjection.frozenIgnoreRulesDigest');
  if (!Array.isArray(value.explicitIncludes) || value.explicitIncludes.length > 128 ||
      !Array.isArray(value.explicitExcludes) || value.explicitExcludes.length > 128) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source selectors exceed the 128-entry bound or are not arrays');
  }
  for (const [kind, selectors] of [
    ['explicitIncludes', value.explicitIncludes],
    ['explicitExcludes', value.explicitExcludes]
  ] as const) {
    const seen = new Set<string>();
    for (const [index, candidate] of selectors.entries()) {
      if (!isRecord(candidate)) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `source ${kind}[${index}] is invalid`);
      }
      rejectUnknownKeys(candidate, kind === 'explicitIncludes'
        ? ['path', 'scope', 'authorizationRef'] : ['path', 'scope'], `SourceProjection.${kind}[${index}]`);
      const selectorPath = requireRootRelativePath(candidate.path, `SourceProjection.${kind}[${index}].path`);
      if (candidate.scope !== 'entry' && candidate.scope !== 'subtree') {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `source ${kind}[${index}] scope is invalid`);
      }
      const key = `${selectorPath}\0${candidate.scope}`;
      if (seen.has(key)) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `source ${kind} has a duplicate selector`);
      }
      seen.add(key);
      if (kind === 'explicitIncludes') {
        requireArtifactRef(candidate.authorizationRef, `SourceProjection.${kind}[${index}].authorizationRef`);
      }
    }
  }
  if (requireSafeInteger(value.maxChangedPaths, 'SourceProjection.maxChangedPaths') > 100_000 ||
      requireSafeInteger(value.maxChangedBytes, 'SourceProjection.maxChangedBytes') > 4 * 1024 * 1024 * 1024) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source projection result ceilings exceed the Kernel Cut');
  }
  requireDigest(value.projectionDigest, 'SourceProjection.projectionDigest');
  const spec = value as SourceProjectionSpec;
  if (digestOmitting(spec, 'projectionDigest') !== spec.projectionDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source projection digest does not rehash');
  }
  return spec;
}

export function decodeWorkspaceEntries(value: unknown): WorkspaceEntryManifest {
  if (!isRecord(value) || value.format !== 'cliq-workspace-entries-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entries have the wrong schema');
  }
  rejectUnknownKeys(
    value,
    ['schemaVersion', 'format', 'entries', 'entryCount', 'byteCount', 'treeDigest'],
    'WorkspaceEntryManifest'
  );
  if (!Array.isArray(value.entries)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entries must be an array');
  }
  const entryCount = requireSafeInteger(value.entryCount, 'WorkspaceEntryManifest.entryCount');
  const byteCount = requireSafeInteger(value.byteCount, 'WorkspaceEntryManifest.byteCount');
  requireDigest(value.treeDigest, 'WorkspaceEntryManifest.treeDigest');
  if (entryCount !== value.entries.length) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entry count does not match the array');
  }
  let priorPath: string | undefined;
  let measuredBytes = 0;
  for (const [index, candidate] of value.entries.entries()) {
    if (!isRecord(candidate)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace entry ${index} must be an object`);
    }
    const entryPath = requireString(candidate.path, `WorkspaceEntryManifest.entries[${index}].path`);
    let normalizedPath: string;
    try {
      normalizedPath = normalizeCanonicalText(entryPath);
    } catch {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace entry ${index} has an invalid path`);
    }
    if (normalizedPath !== entryPath || entryPath.startsWith('/') || entryPath.includes('\\') ||
        entryPath.split('/').some((component) => component === '' || component === '.' ||
          component === '..' || component === '.git')) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace entry ${index} has an invalid path`);
    }
    if (priorPath !== undefined && Buffer.compare(Buffer.from(priorPath), Buffer.from(entryPath)) >= 0) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entry paths must be byte-sorted and unique');
    }
    priorPath = entryPath;
    const mode = requireSafeInteger(candidate.mode, `WorkspaceEntryManifest.entries[${index}].mode`);
    if (candidate.kind === 'directory') {
      rejectUnknownKeys(candidate, ['path', 'kind', 'mode'], `WorkspaceEntryManifest.entries[${index}]`);
      if (mode !== 0o755) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace directory ${entryPath} has a noncanonical mode`);
      }
    } else if (candidate.kind === 'file') {
      rejectUnknownKeys(
        candidate,
        ['path', 'kind', 'mode', 'size', 'blobRef'],
        `WorkspaceEntryManifest.entries[${index}]`
      );
      if (mode !== 0o644 && mode !== 0o755) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace file ${entryPath} has a noncanonical mode`);
      }
      const size = requireSafeInteger(candidate.size, `WorkspaceEntryManifest.entries[${index}].size`);
      requireArtifactRef(candidate.blobRef, `WorkspaceEntryManifest.entries[${index}].blobRef`);
      measuredBytes += size;
    } else if (candidate.kind === 'symlink') {
      rejectUnknownKeys(
        candidate,
        ['path', 'kind', 'mode', 'target', 'targetDigest'],
        `WorkspaceEntryManifest.entries[${index}]`
      );
      const target = requireString(candidate.target, `WorkspaceEntryManifest.entries[${index}].target`);
      let normalizedTarget: string;
      try {
        normalizedTarget = normalizeCanonicalText(target);
      } catch {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace symlink ${entryPath} has an invalid target`);
      }
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(entryPath), target));
      if (normalizedTarget !== target || target.startsWith('/') || target.includes('\\') ||
          resolved === '..' || resolved.startsWith('../') || resolved.split('/').includes('.git')) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace symlink ${entryPath} leaves the admitted root`);
      }
      if (requireDigest(candidate.targetDigest, `WorkspaceEntryManifest.entries[${index}].targetDigest`) !==
          sha256Bytes(Buffer.from(target, 'utf8'))) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace symlink ${entryPath} target digest does not rehash`);
      }
      measuredBytes += Buffer.byteLength(target, 'utf8');
    } else {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace entry ${index} has an invalid kind`);
    }
    if (!Number.isSafeInteger(measuredBytes)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entry byte count exceeds the safe-integer range');
    }
  }
  if (measuredBytes !== byteCount) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entry byte count does not match the array');
  }
  const entries = value as WorkspaceEntryManifest;
  if (canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: entries.entries }) !== entries.treeDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entries digest does not rehash');
  }
  return entries;
}

function validGitHeadRef(ref: string): boolean {
  try {
    if (normalizeCanonicalText(ref) !== ref) return false;
  } catch {
    return false;
  }
  if (!ref.startsWith('refs/heads/') || ref.includes('..') || ref.includes('@{') ||
      /[\u0000-\u0020\u007f~^:?*\[\\]/u.test(ref) || ref.endsWith('.')) return false;
  return !ref.split('/').some((part) => part === '' || part.startsWith('.') || part.endsWith('.lock'));
}

export function decodeSourceManifest(value: unknown): SourceManifest {
  if (!isRecord(value) || value.format !== 'cliq-source-manifest-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source manifest has the wrong schema');
  }
  const hasGit = Object.hasOwn(value, 'git');
  const keys = ['schemaVersion', 'format', 'role', 'workspaceIdentityDigest', 'entriesRef',
    'sourceProjectionRef', 'sourceProjectionDigest', 'frozenIgnoreRulesRef',
    'frozenIgnoreRulesDigest', 'treeDigest', 'manifestDigest', ...(hasGit ? ['git'] : [])];
  if (Object.keys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key)) ||
      (value.role !== 'base' && value.role !== 'result')) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source manifest has an invalid closed shape');
  }
  requireDigest(value.workspaceIdentityDigest, 'SourceManifest.workspaceIdentityDigest');
  requireArtifactRef(value.entriesRef, 'SourceManifest.entriesRef');
  requireArtifactRef(value.sourceProjectionRef, 'SourceManifest.sourceProjectionRef');
  requireDigest(value.sourceProjectionDigest, 'SourceManifest.sourceProjectionDigest');
  requireArtifactRef(value.frozenIgnoreRulesRef, 'SourceManifest.frozenIgnoreRulesRef');
  requireDigest(value.frozenIgnoreRulesDigest, 'SourceManifest.frozenIgnoreRulesDigest');
  requireDigest(value.treeDigest, 'SourceManifest.treeDigest');
  requireDigest(value.manifestDigest, 'SourceManifest.manifestDigest');
  if (hasGit) {
    const git = value.git;
    if (!isRecord(git) || Object.keys(git).length !== 4 ||
        !['repositoryIdentityDigest', 'head', 'indexRef', 'indexTreeObjectId']
          .every((key) => Object.hasOwn(git, key))) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest.git has an invalid closed shape');
    }
    requireDigest(git.repositoryIdentityDigest, 'SourceManifest.git.repositoryIdentityDigest');
    requireArtifactRef(git.indexRef, 'SourceManifest.git.indexRef');
    const tree = requireString(git.indexTreeObjectId, 'SourceManifest.git.indexTreeObjectId');
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(tree)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest.git tree object id is invalid');
    }
    if (!isRecord(git.head) || typeof git.head.kind !== 'string') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest.git head is invalid');
    }
    const head = git.head;
    if (head.kind === 'unborn' || head.kind === 'symbolic') {
      const headKeys = head.kind === 'unborn' ? ['kind', 'branch'] : ['kind', 'ref', 'objectId'];
      const ref = requireString(head.kind === 'unborn' ? head.branch : head.ref, 'SourceManifest.git.head.ref');
      if (Object.keys(head).length !== headKeys.length || !headKeys.every((key) => Object.hasOwn(head, key)) ||
          !validGitHeadRef(ref)) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest.git head ref is invalid');
      }
      if (head.kind === 'symbolic' &&
          (typeof head.objectId !== 'string' ||
            !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(head.objectId))) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest.git head object id is invalid');
      }
    } else if (head.kind === 'detached') {
      if (Object.keys(head).length !== 2 || !Object.hasOwn(head, 'objectId') ||
          typeof head.objectId !== 'string' ||
          !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(head.objectId)) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest.git detached head is invalid');
      }
    } else {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest.git head kind is invalid');
    }
  }
  const manifest = value as SourceManifest;
  if (digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source manifest digest does not rehash');
  }
  return manifest;
}

export function decodeWorkspaceState(value: unknown): WorkspaceStateManifest {
  if (!isRecord(value) || value.format !== 'cliq-workspace-state-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace state has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion', 'format', 'runId', 'baseWorkspaceManifestRef', 'entriesRef',
      'privateGitStateRef', 'invalidatedEphemeralPaths', 'sourceProjectionDigest', 'stateDigest'
    ],
    'WorkspaceStateManifest'
  );
  requireString(value.runId, 'WorkspaceStateManifest.runId');
  requireArtifactRef(value.baseWorkspaceManifestRef, 'WorkspaceStateManifest.baseWorkspaceManifestRef');
  requireArtifactRef(value.entriesRef, 'WorkspaceStateManifest.entriesRef');
  if (value.privateGitStateRef !== undefined) {
    requireArtifactRef(value.privateGitStateRef, 'WorkspaceStateManifest.privateGitStateRef');
  }
  if (
    !Array.isArray(value.invalidatedEphemeralPaths) ||
    value.invalidatedEphemeralPaths.some((entry) => typeof entry !== 'string' || entry.length === 0)
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace invalidated paths are invalid');
  }
  requireDigest(value.sourceProjectionDigest, 'WorkspaceStateManifest.sourceProjectionDigest');
  requireDigest(value.stateDigest, 'WorkspaceStateManifest.stateDigest');
  const state = value as WorkspaceStateManifest;
  if (digestOmitting(state, 'stateDigest') !== state.stateDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace state digest does not rehash');
  }
  return state;
}

export function decodeWorkspaceGenerationIdentity(value: unknown): WorkspaceGenerationIdentityV1 {
  if (
    !isRecord(value) ||
    value.format !== 'cliq-workspace-generation-identity-v1' ||
    value.schemaVersion !== 1
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation identity has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion', 'format', 'generationId', 'runId', 'workspaceIdentityDigest',
      'sourceCheckpointId', 'sourceWorkspaceStateRef', 'sourceWorkspaceStateDigest',
      'sourceTreeDigest', 'creationNonceDigest', 'locator', 'createdAt', 'identityDigest'
    ],
    'WorkspaceGenerationIdentity'
  );
  requireString(value.generationId, 'WorkspaceGenerationIdentity.generationId');
  requireString(value.runId, 'WorkspaceGenerationIdentity.runId');
  requireDigest(value.workspaceIdentityDigest, 'WorkspaceGenerationIdentity.workspaceIdentityDigest');
  requireString(value.sourceCheckpointId, 'WorkspaceGenerationIdentity.sourceCheckpointId');
  requireArtifactRef(value.sourceWorkspaceStateRef, 'WorkspaceGenerationIdentity.sourceWorkspaceStateRef');
  requireDigest(value.sourceWorkspaceStateDigest, 'WorkspaceGenerationIdentity.sourceWorkspaceStateDigest');
  requireDigest(value.sourceTreeDigest, 'WorkspaceGenerationIdentity.sourceTreeDigest');
  requireDigest(value.creationNonceDigest, 'WorkspaceGenerationIdentity.creationNonceDigest');
  if (!isRecord(value.locator)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation locator must be an object');
  }
  if (value.locator.kind === 'linux_directory') {
    rejectUnknownKeys(
      value.locator,
      [
        'kind', 'stateRootIdentityRef', 'stateRootIdentityDigest', 'canonicalRootRelativePath',
        'deviceId', 'directoryFileId', 'ownerUid', 'mode'
      ],
      'WorkspaceGenerationIdentity.locator'
    );
    requireArtifactRef(value.locator.stateRootIdentityRef, 'workspace generation stateRootIdentityRef');
    requireDigest(value.locator.stateRootIdentityDigest, 'workspace generation stateRootIdentityDigest');
    requireString(value.locator.canonicalRootRelativePath, 'workspace generation relative path');
    requireUnsignedDecimal(value.locator.deviceId, 'workspace generation deviceId');
    requireUnsignedDecimal(value.locator.directoryFileId, 'workspace generation directoryFileId');
    requireSafeInteger(value.locator.ownerUid, 'workspace generation ownerUid');
    if (value.locator.mode !== 448) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation directory protection is invalid');
    }
  } else if (value.locator.kind === 'macos_vm_volume') {
    rejectUnknownKeys(
      value.locator,
      [
        'kind', 'stateRootIdentityRef', 'stateRootIdentityDigest',
        'backingStoreCanonicalRootRelativePath', 'backingStoreDeviceId', 'backingStoreFileId',
        'backingStoreOwnerUid', 'backingStoreMode', 'backingStoreLinkCount',
        'vmVolumeReservationId', 'guestVolumeId'
      ],
      'WorkspaceGenerationIdentity.locator'
    );
    requireArtifactRef(value.locator.stateRootIdentityRef, 'workspace generation stateRootIdentityRef');
    requireDigest(value.locator.stateRootIdentityDigest, 'workspace generation stateRootIdentityDigest');
    requireString(value.locator.backingStoreCanonicalRootRelativePath, 'workspace generation backing path');
    requireUnsignedDecimal(value.locator.backingStoreDeviceId, 'workspace generation backing deviceId');
    requireUnsignedDecimal(value.locator.backingStoreFileId, 'workspace generation backing fileId');
    requireSafeInteger(value.locator.backingStoreOwnerUid, 'workspace generation backing ownerUid');
    if (value.locator.backingStoreMode !== 384 || value.locator.backingStoreLinkCount !== 1) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation backing protection is invalid');
    }
    requireString(value.locator.vmVolumeReservationId, 'workspace generation VM reservation');
    requireString(value.locator.guestVolumeId, 'workspace generation guest volume');
  } else {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation locator is invalid');
  }
  requireCanonicalTime(value.createdAt, 'WorkspaceGenerationIdentity.createdAt');
  requireDigest(value.identityDigest, 'WorkspaceGenerationIdentity.identityDigest');
  const identity = value as WorkspaceGenerationIdentityV1;
  if (digestOmitting(identity, 'identityDigest') !== identity.identityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation identity digest does not rehash');
  }
  return identity;
}

export function decodeWorkspaceGenerationSnapshotEvidence(
  value: unknown
): WorkspaceGenerationSnapshotEvidenceV1 {
  if (
    !isRecord(value) ||
    value.format !== 'cliq-workspace-generation-snapshot-evidence-v1' ||
    value.schemaVersion !== 1
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation snapshot evidence has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion', 'format', 'purpose', 'runId', 'generationRef',
      'generationIdentityDigest', 'checkpointId', 'workspaceStateRef', 'workspaceStateDigest',
      'entriesRef', 'treeDigest', 'privateGitStateRef', 'descriptorRewalkComplete',
      'fileFsyncComplete', 'directoryFsyncComplete', 'observedAt', 'evidenceDigest'
    ],
    'WorkspaceGenerationSnapshotEvidence'
  );
  if (value.purpose !== 'materialized_from_checkpoint' && value.purpose !== 'sealed_to_checkpoint') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation snapshot purpose is invalid');
  }
  requireString(value.runId, 'WorkspaceGenerationSnapshotEvidence.runId');
  requireArtifactRef(value.generationRef, 'WorkspaceGenerationSnapshotEvidence.generationRef');
  requireDigest(value.generationIdentityDigest, 'WorkspaceGenerationSnapshotEvidence.generationIdentityDigest');
  requireString(value.checkpointId, 'WorkspaceGenerationSnapshotEvidence.checkpointId');
  requireArtifactRef(value.workspaceStateRef, 'WorkspaceGenerationSnapshotEvidence.workspaceStateRef');
  requireDigest(value.workspaceStateDigest, 'WorkspaceGenerationSnapshotEvidence.workspaceStateDigest');
  requireArtifactRef(value.entriesRef, 'WorkspaceGenerationSnapshotEvidence.entriesRef');
  requireDigest(value.treeDigest, 'WorkspaceGenerationSnapshotEvidence.treeDigest');
  if (value.privateGitStateRef !== undefined) {
    requireArtifactRef(value.privateGitStateRef, 'WorkspaceGenerationSnapshotEvidence.privateGitStateRef');
  }
  requireCanonicalTime(value.observedAt, 'WorkspaceGenerationSnapshotEvidence.observedAt');
  requireDigest(value.evidenceDigest, 'WorkspaceGenerationSnapshotEvidence.evidenceDigest');
  const evidence = value as WorkspaceGenerationSnapshotEvidenceV1;
  if (digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation snapshot evidence does not rehash');
  }
  if (
    evidence.descriptorRewalkComplete !== true ||
    evidence.fileFsyncComplete !== true ||
    evidence.directoryFsyncComplete !== true
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation snapshot is not durable');
  }
  return evidence;
}

export function decodeWorkerIdentity(value: unknown): WorkerIdentity {
  if (!isRecord(value) || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'WorkerIdentity has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion', 'executableRealpath', 'executableDigest', 'pid', 'processStartToken',
      'spawnNonceDigest', 'activationNonceDigest', 'intendedLeaseEpoch', 'launchId',
      'supervisorInstanceId', 'processContainmentRef'
    ],
    'WorkerIdentity'
  );
  const identity = value as WorkerIdentity;
  for (const [label, member] of [
    ['executableRealpath', identity.executableRealpath],
    ['executableDigest', identity.executableDigest],
    ['processStartToken', identity.processStartToken],
    ['spawnNonceDigest', identity.spawnNonceDigest],
    ['activationNonceDigest', identity.activationNonceDigest],
    ['launchId', identity.launchId],
    ['supervisorInstanceId', identity.supervisorInstanceId],
    ['processContainmentRef', identity.processContainmentRef]
  ] as const) {
    requireString(member, `WorkerIdentity.${label}`);
  }
  requireDigest(identity.executableDigest, 'WorkerIdentity.executableDigest');
  requireDigest(identity.spawnNonceDigest, 'WorkerIdentity.spawnNonceDigest');
  requireDigest(identity.activationNonceDigest, 'WorkerIdentity.activationNonceDigest');
  requireArtifactRef(identity.processContainmentRef, 'WorkerIdentity.processContainmentRef');
  if (
    !Number.isSafeInteger(identity.pid) ||
    identity.pid < 1 ||
    !Number.isSafeInteger(identity.intendedLeaseEpoch) ||
    identity.intendedLeaseEpoch < 1
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'WorkerIdentity numeric identity is invalid');
  }
  return identity;
}

const SETTLEMENT_BUDGET_FIELDS = [
  'modelTokens',
  'costMicros',
  'toolCalls',
  'repairAttempts'
] as const;

function decodeSettlementBudget(value: unknown, label: string): BudgetUsage {
  if (!isRecord(value)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be an object`);
  }
  rejectUnknownKeys(value, SETTLEMENT_BUDGET_FIELDS, label);
  return {
    modelTokens: requireSafeInteger(value.modelTokens, `${label}.modelTokens`),
    costMicros: requireSafeInteger(value.costMicros, `${label}.costMicros`),
    toolCalls: requireSafeInteger(value.toolCalls, `${label}.toolCalls`),
    repairAttempts: requireSafeInteger(value.repairAttempts, `${label}.repairAttempts`)
  };
}

function budgetEquation(
  left: BudgetUsage,
  delta: BudgetUsage,
  right: BudgetUsage,
  operation: 'add' | 'subtract'
): boolean {
  return SETTLEMENT_BUDGET_FIELDS.every((field) =>
    operation === 'add'
      ? left[field] + delta[field] === right[field]
      : left[field] - delta[field] === right[field]
  );
}

function budgetLessThanOrEqual(left: BudgetUsage, right: BudgetUsage): boolean {
  return SETTLEMENT_BUDGET_FIELDS.every((field) => left[field] <= right[field]);
}

function budgetEqual(left: BudgetUsage, right: BudgetUsage): boolean {
  return SETTLEMENT_BUDGET_FIELDS.every((field) => left[field] === right[field]);
}

export function decodeBudgetSettlement(value: unknown): BudgetSettlementV1 {
  if (
    !isRecord(value) ||
    value.format !== 'cliq-budget-settlement-v1' ||
    value.schemaVersion !== 1
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'budget settlement has the wrong schema');
  }
  rejectUnknownKeys(
    value,
    [
      'schemaVersion', 'format', 'runId', 'opId', 'attempt', 'preparedJournalSeq',
      'terminalJournalSeq', 'terminalPhase', 'reserved', 'consumed', 'released',
      'budgetConsumedBefore', 'budgetConsumedAfter', 'budgetReservedBefore',
      'budgetReservedAfter', 'settledAt', 'settlementDigest'
    ],
    'BudgetSettlement'
  );
  requireString(value.runId, 'BudgetSettlement.runId');
  requireString(value.opId, 'BudgetSettlement.opId');
  requireSafeInteger(value.attempt, 'BudgetSettlement.attempt');
  requireSafeInteger(value.preparedJournalSeq, 'BudgetSettlement.preparedJournalSeq', 1);
  requireSafeInteger(value.terminalJournalSeq, 'BudgetSettlement.terminalJournalSeq', 2);
  if (!['completed', 'failed', 'unknown'].includes(String(value.terminalPhase))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'budget settlement terminal phase is invalid');
  }
  const reserved = decodeSettlementBudget(value.reserved, 'BudgetSettlement.reserved');
  const consumed = decodeSettlementBudget(value.consumed, 'BudgetSettlement.consumed');
  const released = decodeSettlementBudget(value.released, 'BudgetSettlement.released');
  const consumedBefore = decodeSettlementBudget(
    value.budgetConsumedBefore,
    'BudgetSettlement.budgetConsumedBefore'
  );
  const consumedAfter = decodeSettlementBudget(
    value.budgetConsumedAfter,
    'BudgetSettlement.budgetConsumedAfter'
  );
  const reservedBefore = decodeSettlementBudget(
    value.budgetReservedBefore,
    'BudgetSettlement.budgetReservedBefore'
  );
  const reservedAfter = decodeSettlementBudget(
    value.budgetReservedAfter,
    'BudgetSettlement.budgetReservedAfter'
  );
  if (
    !budgetLessThanOrEqual(consumed, reserved) ||
    !budgetEqual(released, reserved) ||
    !budgetEquation(consumedBefore, consumed, consumedAfter, 'add') ||
    !budgetEquation(reservedBefore, released, reservedAfter, 'subtract')
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'budget settlement equations do not balance');
  }
  requireCanonicalTime(value.settledAt, 'BudgetSettlement.settledAt');
  requireDigest(value.settlementDigest, 'BudgetSettlement.settlementDigest');
  const settlement = value as BudgetSettlementV1;
  if (digestOmitting(settlement, 'settlementDigest') !== settlement.settlementDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'budget settlement digest does not rehash');
  }
  return settlement;
}

export function decodeVerifierSpec(value: unknown): VerifierSpec {
  if (!isRecord(value) || value.format !== 'cliq-verifier-spec-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier spec has the wrong schema');
  }
  const spec = value as VerifierSpec;
  if (digestOmitting(spec, 'specDigest') !== spec.specDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier spec digest does not rehash');
  }
  return spec;
}

export function decodeUnverifiedConsent(value: unknown): DirectUnverifiedConsentV1 {
  if (!isRecord(value) || value.kind !== 'direct_unverified_consent' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'unverified consent has the wrong schema');
  }
  const consent = value as DirectUnverifiedConsentV1;
  if (digestOmitting(consent, 'consentDigest') !== consent.consentDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'unverified consent digest does not rehash');
  }
  if (consent.allowUnverified !== true) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'unverified consent must set allowUnverified=true');
  }
  return consent;
}

export function decodeRunSpec(value: unknown): RunSpec {
  if (!isRecord(value) || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'RunSpec must have schemaVersion=1');
  }
  const spec = value as RunSpec;
  if (spec.operation !== 'agent' && spec.operation !== 'delivery') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'RunSpec operation is invalid');
  }
  requireString(spec.objectiveRef, 'RunSpec.objectiveRef');
  requireString(spec.admittedContextRef, 'RunSpec.admittedContextRef');
  requireString(spec.baseWorkspaceManifestRef, 'RunSpec.baseWorkspaceManifestRef');
  return spec;
}
