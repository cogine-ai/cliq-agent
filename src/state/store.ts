import { constants, type Stats } from 'node:fs';
import { chmod, lstat, mkdir, open } from 'node:fs/promises';
import path from 'node:path';

import {
  KERNEL_CAS_DIRECTORY,
  KERNEL_DATABASE_FILENAME,
  KERNEL_SQLITE_APPLICATION_ID,
  KERNEL_STATE_SCHEMA_VERSION
} from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import {
  digestOmitting,
  encodeCanonicalTime,
  identityHash,
  normalizeAbsolutePath,
  sha256Bytes,
  unsignedDecimalId
} from '../kernel/identity.js';
import type {
  KernelGenerationIdentityV1,
  LocalControlChannelIdentityV1,
  PlatformProcessIdentityV1,
  RecoveryClosureV1,
  Run,
  Session,
  StateLockIdentityV1,
  StateOwnerAcquisitionEvidenceV1,
  StateOwnerRecordV1,
  StateRootIdentityV1
} from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { insertGenesisTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError } from './errors.js';
import { admitRun, type AdmitRunInput, type AdmitRunResult } from './reducers/admission.js';
import { createSession, type CreateSessionInput, type CreateSessionResult } from './reducers/session.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readRun, readSession } from './rows.js';
import { applyKernelSchema, KERNEL_SCHEMA_SQL, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { hostPlatform } from './workspace-identity.js';

export type { AdmitRunInput, AdmitRunResult, CreateSessionInput, CreateSessionResult };

function requireEffectiveUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'state store requires a POSIX effective uid');
  }
  return process.geteuid();
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

async function ensurePrivateDirectory(directory: string): Promise<void> {
  try {
    await mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  await chmod(directory, 0o700);
  const info = await lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory() || (info.mode & 0o7777) !== 0o700) {
    throw new KernelStorageError('INVALID_REQUEST', `${directory} must be a 0700 directory`);
  }
}

async function ensureLockFile(lockPath: string): Promise<Stats> {
  try {
    const handle = await open(
      lockPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600
    );
    await handle.close();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  const existing = await lstat(lockPath);
  if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) {
    throw new KernelStorageError('INVALID_REQUEST', 'state-owner lock must be a 0600 regular file with link count 1');
  }
  await chmod(lockPath, 0o600);
  const info = await lstat(lockPath);
  if (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1 || (info.mode & 0o7777) !== 0o600) {
    throw new KernelStorageError('INVALID_REQUEST', 'state-owner lock must be a 0600 regular file with link count 1');
  }
  return info;
}

export class StateStore {
  private constructor(
    readonly stateRoot: string,
    private readonly driver: SqliteDriver,
    readonly artifacts: ArtifactCatalog,
    readonly ownerEpoch: number
  ) {}

  static async open(stateRoot: string): Promise<StateStore> {
    if (process.platform !== 'darwin' && process.platform !== 'linux') {
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', `state store is unsupported on ${process.platform}`);
    }
    await assertPrivateStateRoot(stateRoot);
    const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
    const runtimeRoot = path.join(stateRoot, 'runtime');
    await ensurePrivateDirectory(casRoot);
    await ensurePrivateDirectory(runtimeRoot);

    const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    applyKernelSchema(driver);
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(casRoot));
    const ownerEpoch = await bootstrapFreshEmpty(stateRoot, driver, artifacts);
    return new StateStore(stateRoot, driver, artifacts, ownerEpoch);
  }

  createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    return createSession(this.driver, this.artifacts, this.ownerEpoch, input);
  }

  admitRun(input: AdmitRunInput): Promise<AdmitRunResult> {
    return admitRun(this.driver, this.artifacts, this.ownerEpoch, input);
  }

  getSession(sessionId: string): Session {
    return readSession(this.driver, sessionId);
  }

  getRun(runId: string): Run {
    return readRun(this.driver, runId);
  }

  readRecoveryClosure(runId: string): Promise<RecoveryClosureV1> {
    return readRecoveryClosure(this.driver, this.artifacts, runId);
  }

  close(): void {
    this.driver.close();
  }
}

export async function openStateStore(stateRoot: string): Promise<StateStore> {
  return StateStore.open(stateRoot);
}

async function bootstrapFreshEmpty(
  stateRoot: string,
  driver: SqliteDriver,
  artifacts: ArtifactCatalog
): Promise<number> {
  const existingOwner = driver
    .prepare(`SELECT owner_epoch FROM state_owners WHERE state = 'active'`)
    .get<{ owner_epoch: unknown }>();
  const fence = readTimeFence(driver);
  if (existingOwner !== undefined && fence !== undefined) {
    return Number(existingOwner.owner_epoch);
  }
  if (existingOwner !== undefined || fence !== undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner and time fence must be created together');
  }

  const now = sampleCanonicalNow();
  const platform = hostPlatform();
  const uid = requireEffectiveUid();
  const rootInfo = await lstat(stateRoot);
  const lockInfo = await ensureLockFile(path.join(stateRoot, 'runtime', 'state-owner.lock'));

  const stateRootIdentity: StateRootIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-state-root-identity-v1',
    platform,
    canonicalAbsolutePath: stateRoot,
    ownerUid: uid,
    deviceId: unsignedDecimalId(rootInfo.dev),
    directoryFileId: unsignedDecimalId(rootInfo.ino),
    mode: 448,
    openedNoFollow: true,
    layoutVersion: 1,
    identityDigest: ''
  };
  stateRootIdentity.identityDigest = digestOmitting(stateRootIdentity, 'identityDigest');
  const stateRootArtifact = await artifacts.publishCanonical(stateRootIdentity, 'cliq-state-root-identity-v1');

  const processIdentity: PlatformProcessIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-platform-process-identity-v1',
    platform,
    pid: process.pid,
    processStartToken: `${process.pid}:${process.ppid}:${encodeCanonicalTime(Date.now())}`,
    ownerUid: uid,
    executableImageDigest: sha256Bytes(Buffer.from(process.execPath, 'utf8')),
    observedAt: now,
    identityDigest: ''
  };
  processIdentity.identityDigest = digestOmitting(processIdentity, 'identityDigest');
  const processArtifact = await artifacts.publishCanonical(processIdentity, 'cliq-platform-process-identity-v1');

  const lockIdentity: StateLockIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-state-lock-identity-v1',
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    canonicalRootRelativePath: 'runtime/state-owner.lock',
    deviceId: unsignedDecimalId(lockInfo.dev),
    fileId: unsignedDecimalId(lockInfo.ino),
    ownerUid: lockInfo.uid,
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
    userVersion: KERNEL_STATE_SCHEMA_VERSION,
    schemaDigest,
    manifestDigest: ''
  };
  schemaManifest.manifestDigest = digestOmitting(schemaManifest, 'manifestDigest');
  const schemaArtifact = await artifacts.publishCanonical(schemaManifest, 'cliq-kernel-schema-manifest-v1');

  const emptyDatabase = {
    schemaVersion: 1,
    format: 'cliq-kernel-empty-database-v1',
    applicationId: KERNEL_SQLITE_APPLICATION_ID,
    userVersion: readSchemaUserVersion(driver),
    contentDigest: canonicalSha256({ applicationId: KERNEL_SQLITE_APPLICATION_ID, userVersion: 1, tables: 20 })
  };
  const databaseArtifact = await artifacts.publishCanonical(emptyDatabase, 'cliq-kernel-empty-database-v1');

  const casNamespace = {
    schemaVersion: 1,
    format: 'cliq-cas-namespace-manifest-v1',
    snapshotBoundary: 'generation_birth',
    namespaceId: identityHash('cliq-cas-namespace-v1', stateRootIdentity.identityDigest, 'cas'),
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    canonicalRootRelativePath: KERNEL_CAS_DIRECTORY,
    ownerUid: uid,
    deviceId: unsignedDecimalId(rootInfo.dev),
    directoryFileId: unsignedDecimalId(rootInfo.ino),
    mode: 448,
    entries: [] as Array<{ artifactRef: string; byteCount: number }>,
    objectCount: 0,
    totalBytes: 0,
    rootDigest: canonicalSha256([]),
    manifestDigest: ''
  };
  casNamespace.manifestDigest = digestOmitting(casNamespace, 'manifestDigest');
  const casArtifact = await artifacts.publishCanonical(casNamespace, 'cliq-cas-namespace-manifest-v1');

  const generation: KernelGenerationIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-kernel-generation-identity-v1',
    generationId: identityHash('cliq-kernel-generation-v1', stateRootIdentity.identityDigest, 'fresh_empty'),
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
    stateSchemaVersion: 1,
    generationDigest: '',
    origin: 'fresh_empty',
    pristineSchemaManifestRef: schemaArtifact.ref,
    pristineSchemaManifestDigest: schemaManifest.manifestDigest,
    pristineSchemaDigest: schemaDigest
  };
  generation.generationDigest = digestOmitting(generation, 'generationDigest');
  const generationArtifact = await artifacts.publishCanonical(generation, 'cliq-kernel-generation-identity-v1');

  const supervisorInstanceId = identityHash('cliq-supervisor-instance-v1', processIdentity.identityDigest, now);
  const instanceNonceDigest = sha256Bytes(Buffer.from(`${supervisorInstanceId}:${now}`, 'utf8'));
  const acquisition: StateOwnerAcquisitionEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-state-owner-acquisition-evidence-v1',
    ownerEpoch: 1,
    supervisorInstanceId,
    runtimeBundleRef: schemaArtifact.ref,
    runtimeBundleManifestDigest: schemaManifest.manifestDigest,
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

  const owner: StateOwnerRecordV1 = {
    schemaVersion: 1,
    ownerEpoch: 1,
    supervisorInstanceId,
    runtimeBundleRef: schemaArtifact.ref,
    runtimeBundleManifestDigest: schemaManifest.manifestDigest,
    supervisorEntryId: 'state-store',
    supervisorEntryVersion: 'm1',
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

  driver.transaction((connection) => {
    insertGenesisTimeFence(connection, 1, now);
    connection
      .prepare(
        `INSERT INTO state_owners (owner_epoch, supervisor_instance_id, record_json, state, row_digest)
         VALUES (1, ?, ?, 'active', ?)`
      )
      .run(supervisorInstanceId, JSON.stringify(owner), owner.rowDigest);
  });
  return 1;
}

export async function publishInProcessChannel(
  store: StateStore,
  principalId: string,
  client: LocalControlChannelIdentityV1['client'] = 'cli'
): Promise<{ channelIdentityRef: string; channelIdentityDigest: string }> {
  const now = sampleCanonicalNow();
  const processIdentity: PlatformProcessIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-platform-process-identity-v1',
    platform: hostPlatform(),
    pid: process.pid,
    processStartToken: `${process.pid}:${process.ppid}`,
    ownerUid: requireEffectiveUid(),
    executableImageDigest: sha256Bytes(Buffer.from(process.execPath, 'utf8')),
    observedAt: now,
    identityDigest: ''
  };
  processIdentity.identityDigest = digestOmitting(processIdentity, 'identityDigest');
  const processArtifact = await store.artifacts.publishCanonical(
    processIdentity,
    'cliq-platform-process-identity-v1'
  );
  const channel: LocalControlChannelIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-local-control-channel-identity-v1',
    principalIdentityRef: processArtifact.ref,
    principalIdentityDigest: processIdentity.identityDigest,
    principalId,
    client,
    transport: {
      kind: 'in_process',
      processIdentityRef: processArtifact.ref,
      processIdentityDigest: processIdentity.identityDigest
    },
    openedAt: now,
    channelNonceDigest: sha256Bytes(Buffer.from(`${principalId}:${now}`, 'utf8')),
    channelIdentityDigest: ''
  };
  channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
  const channelArtifact = await store.artifacts.publishCanonical(channel, 'cliq-local-control-channel-identity-v1');
  return { channelIdentityRef: channelArtifact.ref, channelIdentityDigest: channel.channelIdentityDigest };
}
