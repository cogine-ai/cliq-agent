import type { Stats } from 'node:fs';
import { lstat, mkdir, readFile, readdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
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
  identityHash,
  normalizeAbsolutePath,
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
import { ArtifactCatalog } from './artifacts.js';
import {
  insertGenesisTimeFence,
  readTimeFence,
  recoverRegressedTimeFence,
  sampleCanonicalNow,
  transferTimeFenceOwner,
  type TimeFenceAdvance
} from './canonical-time.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError } from './errors.js';
import { assertStateOwnerLock, loadNativeStateOwner, type HeldStateOwnerLock, type NativeStateOwner } from './native-owner.js';
import {
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
import { readRun, readSession } from './rows.js';
import { applyKernelSchema, KERNEL_SCHEMA_SQL, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import {
  assertActiveStateOwner,
  assertContiguousStateOwnerHistory,
  contextFromStateOwner,
  gracefullyReleaseStateOwner,
  readActiveStateOwner,
  readLatestStateOwner,
  insertStateOwnerArtifacts,
  type StateOwnerContext
} from './state-owner.js';
import { hostPlatform } from './workspace-identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';

/** Trusted Supervisor bootstrap input, never loaded from Run/workspace configuration. Required again on signed-owner reopen. */
export type StateStoreRuntimeAuthority = { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[] };

export type {
  LoadAgentRunInput,
  ActivateWorkerLeaseInput,
  AdmitRunInput,
  AdmitRunResult,
  BeginGenerationCheckpointInput,
  BeginGenerationRevocationInput,
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
        `refusing fresh_empty genesis over non-empty authority table ${table}`
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

let currentProcessBasePromise:
  | Promise<{ processStartToken: string; executableImageDigest: string }>
  | undefined;

async function currentProcessBase(native: NativeStateOwner): Promise<{
  processStartToken: string;
  executableImageDigest: string;
}> {
  currentProcessBasePromise ??= (async () => {
    const executableImageDigest = sha256Bytes(await readFile(process.execPath));
    return {
      processStartToken: native.processStartToken(),
      executableImageDigest
    };
  })();
  return currentProcessBasePromise;
}

async function currentProcessIdentity(native: NativeStateOwner, observedAt: string): Promise<PlatformProcessIdentityV1> {
  const base = await currentProcessBase(native);
  const identity: PlatformProcessIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-platform-process-identity-v1',
    platform: hostPlatform(),
    pid: process.pid,
    processStartToken: base.processStartToken,
    ownerUid: requireEffectiveUid(),
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
    throw new KernelStorageError('RECOVERY_REQUIRED', 'active StateOwner acquisition closure does not match');
  }
  return contextFromStateOwner(
    owner,
    filesystem,
    { ref: lockIdentity.stateRootIdentityRef, digest: lockIdentity.stateRootIdentityDigest }
  );
}

export class StateStore {
  private closed = false;
  private released = false;
  private closing: Promise<void> | undefined;

  private constructor(
    readonly stateRoot: string,
    private readonly driver: SqliteDriver,
    readonly artifacts: ArtifactCatalog,
    private readonly owner: StateOwnerContext
  ) {}

  get ownerEpoch(): number {
    return this.owner.ownerEpoch;
  }

  get stateRootIdentity(): { ref: string; digest: string } {
    return {
      ref: this.owner.stateRootIdentityRef,
      digest: this.owner.stateRootIdentityDigest
    };
  }

  static async open(stateRoot: string, runtimeAuthority?: StateStoreRuntimeAuthority): Promise<StateStore> {
    runtimeAuthority = runtimeAuthority === undefined ? undefined : immutableSnapshot(runtimeAuthority);
    if (process.platform !== 'darwin' && process.platform !== 'linux') {
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', `state store is unsupported on ${process.platform}`);
    }
    if (runtimeAuthority) {
      verifyRuntimeBundle(runtimeAuthority.bundle, runtimeAuthority.releaseKeys);
    }
    const native = await loadNativeStateOwner(runtimeAuthority?.bundle);
    if (runtimeAuthority) {
      const supervisor = runtimeAuthority.bundle.entries.find((entry) => entry.role === 'supervisor')!;
      if (supervisor.digest !== (await currentProcessBase(native)).executableImageDigest ||
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
      } else if (preflightSchemaVersion === KERNEL_STATE_SCHEMA_VERSION) {
        const activeOwner = driver
          .prepare(`SELECT owner_epoch FROM state_owners WHERE state = 'active' LIMIT 1`)
          .get<{ owner_epoch: unknown }>();
        if (activeOwner !== undefined) {
          throw new KernelStorageError(
            'RECOVERY_REQUIRED',
            `state owner epoch ${String(activeOwner.owner_epoch)} is still active`
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
      const owner = await acquireOrBootstrapStateOwner(stateRoot, driver, artifacts, native, heldLock, runtimeAuthority?.bundle);
      const ownerContext = await stateOwnerContextFromArtifacts(stateRoot, artifacts, owner, heldLock);
      return new StateStore(stateRoot, driver, artifacts, ownerContext);
    } catch (error) {
      try {
        driver?.close();
      } catch {
        // Preserve the open/acquisition failure as the primary diagnostic.
      }
      heldLock.close();
      throw error;
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
    return reserveWorkerLaunch(this.driver, this.artifacts, this.owner, input);
  }

  recordWorkerPreactivated(input: RecordWorkerPreactivatedInput) {
    return recordWorkerPreactivated(this.driver, this.artifacts, this.owner, input);
  }

  activateWorkerLease(input: ActivateWorkerLeaseInput) {
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

  getRun(runId: string): Run {
    return readRun(this.driver, runId);
  }

  readRecoveryClosure(runId: string): Promise<RecoveryClosureV1> {
    return readRecoveryClosure(this.driver, this.artifacts, runId);
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
    const attempt = (async () => {
      if (!this.released) {
        await gracefullyReleaseStateOwner(this.driver, this.artifacts, this.owner);
        this.released = true;
      }
      this.driver.close();
      this.owner.filesystem.close();
      this.closed = true;
    })();
    this.closing = attempt.catch((error: unknown) => {
      this.closing = undefined;
      throw error;
    });
    return this.closing;
  }
}

export async function openStateStore(stateRoot: string, runtimeAuthority?: StateStoreRuntimeAuthority): Promise<StateStore> {
  return StateStore.open(stateRoot, runtimeAuthority);
}

async function acquireOrBootstrapStateOwner(
  stateRoot: string,
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  native: NativeStateOwner,
  heldLock: HeldStateOwnerLock,
  runtimeBundle?: RuntimeBundleManifest
): Promise<Extract<StateOwnerRecordV1, { state: 'active' }>> {
  assertContiguousStateOwnerHistory(driver);
  const existingOwner = readActiveStateOwner(driver);
  const fence = readTimeFence(driver);
  if (existingOwner !== undefined) {
    throw new KernelStorageError(
      'RECOVERY_REQUIRED',
      `state owner epoch ${existingOwner.ownerEpoch} is still active`
    );
  }
  const latestOwner = readLatestStateOwner(driver);
  if (latestOwner !== undefined) {
    if (fence === undefined || fence.stateOwnerEpoch !== latestOwner.ownerEpoch) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner history and time fence do not match');
    }
    if (latestOwner.state !== 'terminal' || latestOwner.terminalReason !== 'graceful_release') {
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
    return acquireAfterGracefulRelease(stateRoot, driver, artifacts, latestOwner, native, heldLock);
  }
  if (fence !== undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence exists without state owner history');
  }
  assertFreshAuthorityDatabaseEmpty(driver);

  const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
  const existingCasEntries = await readdir(casRoot);
  if (existingCasEntries.length !== 0) {
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

  const stateRootIdentity: StateRootIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-state-root-identity-v1',
    platform,
    canonicalAbsolutePath: stateRoot,
    ownerUid: uid,
    deviceId: heldLock.root.deviceId,
    directoryFileId: heldLock.root.fileId,
    mode: 448,
    openedNoFollow: true,
    layoutVersion: 1,
    identityDigest: ''
  };
  stateRootIdentity.identityDigest = digestOmitting(stateRootIdentity, 'identityDigest');
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
    userVersion: KERNEL_STATE_SCHEMA_VERSION,
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
    userVersion: readSchemaUserVersion(driver),
    contentDigest: canonicalSha256({
      applicationId: KERNEL_SQLITE_APPLICATION_ID,
      userVersion: KERNEL_STATE_SCHEMA_VERSION,
      tables: AUTHORITY_TABLES.length
    })
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
    deviceId: unsignedDecimalId(casInfo.dev),
    directoryFileId: unsignedDecimalId(casInfo.ino),
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

  driver.transaction((connection) => {
    assertStateOwnerLock(heldLock);
    assertFreshAuthorityDatabaseEmpty(connection);
    insertStateOwnerArtifacts(
      connection,
      [
        stateRootArtifact,
        processArtifact,
        lockArtifact,
        schemaArtifact,
        ...(runtimeBundle ? [runtimeArtifact] : []),
        databaseArtifact,
        casArtifact,
        generationArtifact,
        acquisitionArtifact
      ],
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

async function acquireAfterGracefulRelease(
  stateRoot: string,
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  prior: Extract<StateOwnerRecordV1, { state: 'terminal' }>,
  native: NativeStateOwner,
  heldLock: HeldStateOwnerLock
): Promise<Extract<StateOwnerRecordV1, { state: 'active' }>> {
  await stateOwnerFilesystemFromArtifacts(stateRoot, artifacts, prior, heldLock);
  const transition = decodeStateOwnerTransitionEvidence(
    await artifacts.readCanonical(prior.transitionEvidenceRef)
  );
  if (
    transition.kind !== 'graceful_release' ||
    transition.evidenceDigest !== prior.transitionEvidenceDigest ||
    transition.priorOwnerEpoch !== prior.ownerEpoch ||
    transition.priorSupervisorInstanceId !== prior.supervisorInstanceId ||
    transition.priorProcessIdentityRef !== prior.processIdentityRef ||
    transition.priorProcessIdentityDigest !== prior.processIdentityDigest ||
    transition.stateLockIdentityRef !== prior.stateLockIdentityRef ||
    transition.stateLockIdentityDigest !== prior.stateLockIdentityDigest
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'graceful owner transition evidence does not match');
  }

  const currentFence = readTimeFence(driver);
  if (currentFence === undefined || currentFence.stateOwnerEpoch !== prior.ownerEpoch) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence does not match graceful owner history');
  }
  const acquiredAt = sampleCanonicalNow();
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
    kind: 'acquire_after_graceful_release',
    priorOwnerEpoch: prior.ownerEpoch,
    priorTerminalRowDigest: prior.rowDigest,
    priorTransitionEvidenceRef: prior.transitionEvidenceRef,
    priorTransitionEvidenceDigest: prior.transitionEvidenceDigest,
    priorTerminalReason: 'graceful_release'
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
    if (readActiveStateOwner(connection) !== undefined) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'another state owner acquired authority');
    }
    const lockedPrior = readLatestStateOwner(connection);
    if (
      lockedPrior === undefined ||
      lockedPrior.state !== 'terminal' ||
      lockedPrior.ownerEpoch !== prior.ownerEpoch ||
      lockedPrior.rowDigest !== prior.rowDigest ||
      lockedPrior.terminalReason !== 'graceful_release'
    ) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'prior state owner changed during acquisition');
    }
    fenceOutcome = transferTimeFenceOwner(connection, prior.ownerEpoch, ownerEpoch, acquiredAt);
    insertStateOwnerArtifacts(connection, [processArtifact, acquisitionArtifact], artifactCreatedAt);
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
  principalId: string,
  client: LocalControlChannelIdentityV1['client'] = 'cli'
): Promise<{ channelIdentityRef: string; channelIdentityDigest: string }> {
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
    principalId,
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
    principalId,
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
  return { channelIdentityRef: channelArtifact.ref, channelIdentityDigest: channel.channelIdentityDigest };
}
